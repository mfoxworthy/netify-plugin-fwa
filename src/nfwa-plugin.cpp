#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <string>

extern "C" {
#include <uci.h>
#include <libnftables/nftables.h>
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

// ── Reload (called on startup and SIGHUP by netifyd) ─────────────────────────

void nfwaPlugin::Reload()
{
    LoadConfig();
    nd_printf("%s: config loaded, %zu mappings, ttl=%us\n",
        GetTag().c_str(), config_.mappings.size(), config_.set_ttl);
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
    std::lock_guard<std::mutex> lg(config_mutex_);
    for (const auto &m : config_.mappings) {
        if (m.type == NfwaMapping::APP_TAG) {
            if (!flow->app.tag.empty() && flow->app.tag == m.key)
                return m.set;
        } else {
            if (!flow->app.category_tag.empty() && flow->app.category_tag == m.key)
                return m.set;
        }
    }
    return {};
}

// ── ProcessFlow (stub — implementation in Task 4) ────────────────────────────

void nfwaPlugin::ProcessFlow(ndDetectionEvent /*event*/, ndFlow * /*flow*/)
{
    // Task 4
}

// ── Plugin factory (loaded by netifyd via dlopen/dlsym) ──────────────────────

extern "C" ndPlugin *CreatePlugin(const string &tag)
{
    return new nfwaPlugin(tag);
}
