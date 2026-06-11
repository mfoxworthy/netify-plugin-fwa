#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <fstream>
#include <string>

extern "C" {
#include <uci.h>
#include <nftables/libnftables.h>
}

#include "nfwa-plugin.hpp"

using namespace std;

// ── Constructor / Destructor ─────────────────────────────────────────────────

nfwaPlugin::nfwaPlugin(const string &tag)
    : ndPluginDetection(tag)
{
    nft_ctx_ = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft_ctx_)
        throw std::runtime_error("nfwaPlugin: failed to create nft context");
    nft_ctx_output_set_flags(nft_ctx_, NFT_CTX_OUTPUT_JSON);

    Reload();
    InitNftables();
}

nfwaPlugin::~nfwaPlugin()
{
    Join();
    if (nft_ctx_) nft_ctx_free(nft_ctx_);
}

// ── GetVersion ───────────────────────────────────────────────────────────────

void nfwaPlugin::GetVersion(string &version)
{
    version = PACKAGE_VERSION;
}

// ── Reload (called on startup) ────────────────────────────────────────────────

void nfwaPlugin::Reload()
{
    LoadCategoryMap();
    LoadConfig();
    nd_printf("%s: config loaded, %zu mappings, ttl=%us\n",
        GetTag().c_str(), config_.mappings.size(), config_.set_ttl);
}

// ── LoadCategoryMap ───────────────────────────────────────────────────────────
// Reads the netifyd apps JSON to build a category-tag → id map.
// The file contains an "application_tag_index" object: { "tag": id, ... }

void nfwaPlugin::LoadCategoryMap()
{
    const std::string path = std::string(ND_DATADIR) + "/netifyd-apps.json";
    std::unordered_map<std::string, nd_cat_id_t> m;

    std::ifstream f(path);
    if (f.is_open()) {
        try {
            auto j = json::parse(f);
            auto it = j.find("application_tag_index");
            if (it != j.end()) {
                for (auto &kv : it->items())
                    m[kv.key()] = (nd_cat_id_t)kv.value().get<unsigned>();
            }
            nd_printf("%s: loaded %zu category tags from %s\n",
                GetTag().c_str(), m.size(), path.c_str());
        } catch (const std::exception &ex) {
            nd_printf("%s: warning: failed to parse %s: %s\n",
                GetTag().c_str(), path.c_str(), ex.what());
        }
    } else {
        nd_printf("%s: warning: apps JSON not found: %s\n",
            GetTag().c_str(), path.c_str());
    }

    std::lock_guard<std::mutex> lg(config_mutex_);
    cat_tag_to_id_ = std::move(m);
}

// ── LoadConfig ───────────────────────────────────────────────────────────────

void nfwaPlugin::LoadConfig()
{
    NfwaConfig cfg;

    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return;

    struct uci_package *pkg = nullptr;
    if (uci_load(ctx, "netify-fwa", &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return;
    }

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "globals") == 0) {
            struct uci_option *o = uci_lookup_option(ctx, s, "set_ttl");
            if (o && o->type == UCI_TYPE_STRING)
                cfg.set_ttl = (unsigned)atoi(o->v.string);
            continue;
        }

        if (strcmp(s->type, "mapping") == 0) {
            NfwaMapping m;
            struct uci_option *app_opt = uci_lookup_option(ctx, s, "application");
            struct uci_option *cat_opt = uci_lookup_option(ctx, s, "app_category");
            struct uci_option *set_opt = uci_lookup_option(ctx, s, "set");

            if (!set_opt || set_opt->type != UCI_TYPE_STRING) continue;
            m.set = set_opt->v.string;

            if (app_opt && app_opt->type == UCI_TYPE_STRING) {
                m.type = NfwaMapping::APP_TAG;
                m.key  = app_opt->v.string;
                cfg.mappings.push_back(m);
            } else if (cat_opt && cat_opt->type == UCI_TYPE_STRING) {
                m.type = NfwaMapping::APP_CATEGORY;
                m.key  = cat_opt->v.string;
                // Resolve tag → id while we still hold cat_tag_to_id_
                {
                    std::lock_guard<std::mutex> lg(config_mutex_);
                    auto it = cat_tag_to_id_.find(m.key);
                    if (it != cat_tag_to_id_.end())
                        m.cat_id = it->second;
                    else
                        nd_printf("%s: warning: unknown category tag '%s'\n",
                            GetTag().c_str(), m.key.c_str());
                }
                cfg.mappings.push_back(m);
            }
        }
    }

    uci_free_context(ctx);

    std::lock_guard<std::mutex> lg(config_mutex_);
    config_ = std::move(cfg);
}

// ── InitNftables ─────────────────────────────────────────────────────────────

void nfwaPlugin::InitNftables()
{
    // Create table and set idempotently — "add" is a no-op if they already exist.
    // sd-wrt-policy also does this, so both can race safely.
    const char *cmds =
        "add table inet sd_wrt\n"
        "add set inet sd_wrt sdwrt_interactive "
            "{ type ipv4_addr; flags timeout; }\n";

    if (nft_run_cmd_from_buffer(nft_ctx_, cmds) != 0)
        nd_printf("%s: warning: nftables init returned non-zero\n", GetTag().c_str());
}

// ── Entry (background thread — minimal, all work done in ProcessFlow) ─────────

void *nfwaPlugin::Entry(void)
{
    nd_printf("%s: started\n", GetTag().c_str());
    while (!ShouldTerminate())
        sleep(1);
    nd_printf("%s: stopped\n", GetTag().c_str());
    return nullptr;
}

// ── AddToSet / RemoveFromSet ──────────────────────────────────────────────────

void nfwaPlugin::AddToSet(const string &set, const string &ip, unsigned ttl)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "add element inet sd_wrt %s { %s timeout %us }\n",
        set.c_str(), ip.c_str(), ttl);
    nft_run_cmd_from_buffer(nft_ctx_, cmd);
}

void nfwaPlugin::RemoveFromSet(const string &set, const string &ip)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "delete element inet sd_wrt %s { %s }\n",
        set.c_str(), ip.c_str());
    // Ignore errors — element may have already expired via TTL
    nft_run_cmd_from_buffer(nft_ctx_, cmd);
}

// ── MatchMapping ─────────────────────────────────────────────────────────────

string nfwaPlugin::MatchMapping(const ndFlow *flow) const
{
    // flow->detected_application_name is the app tag string (e.g. "netify.zoom")
    const char *app_tag = flow->detected_application_name;
    // flow->category.application is the numeric category id
    nd_cat_id_t cat_id = flow->category.application;

    std::lock_guard<std::mutex> lg(config_mutex_);
    for (const auto &m : config_.mappings) {
        if (m.type == NfwaMapping::APP_TAG) {
            if (app_tag && app_tag[0] != '\0' && m.key == app_tag)
                return m.set;
        } else {
            if (m.cat_id != 0 && cat_id == m.cat_id)
                return m.set;
        }
    }
    return {};
}

// ── ProcessFlow ──────────────────────────────────────────────────────────────

void nfwaPlugin::ProcessFlow(ndDetectionEvent event, ndFlow *flow)
{
    if (event == ndPluginDetection::EVENT_EXPIRING) {
        string set = MatchMapping(flow);
        if (!set.empty())
            // upper_addr is the server (responding) side — the destination IP we route by
            RemoveFromSet(set, flow->upper_addr.GetString());
        return;
    }

    if (event == ndPluginDetection::EVENT_NEW ||
        event == ndPluginDetection::EVENT_UPDATED) {
        // Only act on flows that have been classified (app name or category set)
        bool has_app = (flow->detected_application_name != nullptr &&
                        flow->detected_application_name[0] != '\0');
        bool has_cat = (flow->category.application != 0);
        if (has_app || has_cat) {
            string set = MatchMapping(flow);
            if (!set.empty()) {
                unsigned ttl;
                {
                    std::lock_guard<std::mutex> lg(config_mutex_);
                    ttl = config_.set_ttl;
                }
                // upper_addr is the server (responding) side — the destination IP we route by
                AddToSet(set, flow->upper_addr.GetString(), ttl);
            }
        }
        return;
    }
}

// ── Plugin factory — matches ndPluginInit macro in nd-plugin.h ───────────────

ndPluginInit(nfwaPlugin);
