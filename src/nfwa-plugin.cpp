#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <fstream>
#include <sstream>
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

    // Load whatever API data is already cached; Entry() will refresh if stale.
    LoadNetifyData();
    LoadConfig();
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

// ── Reload ───────────────────────────────────────────────────────────────────

void nfwaPlugin::Reload()
{
    LoadNetifyData();
    LoadConfig();
    nd_printf("%s: reloaded, %zu mappings\n",
        GetTag().c_str(), config_.mappings.size());
}

// ── NeedsRefresh ─────────────────────────────────────────────────────────────
// True if the API cache is missing or older than NFWA_CACHE_TTL seconds.

bool nfwaPlugin::NeedsRefresh() const
{
    struct stat st;
    if (stat(NFWA_CACHE_CATIDX, &st) != 0) return true;
    return (time(nullptr) - st.st_mtime) > NFWA_CACHE_TTL;
}

// ── FetchPaginated ────────────────────────────────────────────────────────────
// Downloads all pages of a paginated Netify API endpoint via a single popen()
// call to nfwa-fetch.sh.  The script runs uclient-fetch per page from inside
// sh (~1 MB), so we only fork netifyd (141 MB) once instead of once per page.
// The script outputs one compact JSON object per line; we parse them as they
// arrive so the pipe never blocks.

bool nfwaPlugin::FetchPaginated(const string &endpoint, json &items)
{
    items = json::array();

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        NFWA_FETCH_SCRIPT " '" NFWA_API_BASE "' '%s'",
        endpoint.c_str());

    FILE *f = popen(cmd, "r");
    if (!f) return false;

    bool ok = false;
    string line;
    char buf[8192];

    while (fgets(buf, sizeof(buf), f)) {
        line += buf;
        if (line.empty() || line.back() != '\n')
            continue;  // fgets hit its buffer limit; keep accumulating

        line.pop_back();  // strip trailing newline

        if (line.empty() || line[0] != '{') {
            line.clear();
            continue;
        }

        try {
            auto page_result = json::parse(line);
            line.clear();

            if (page_result.value("status_code", -1) != 0) {
                nd_printf("%s: warning: API error from %s\n",
                    GetTag().c_str(), endpoint.c_str());
                pclose(f);
                return false;
            }

            const auto &data = page_result["data"];
            if (data.is_array())
                items.insert(items.end(), data.begin(), data.end());
            else if (data.is_object())
                for (auto &[k, v] : data.items())
                    items.push_back(v);

            ok = true;
        } catch (...) {
            nd_printf("%s: warning: JSON parse error from %s\n",
                GetTag().c_str(), endpoint.c_str());
            line.clear();
        }
    }

    pclose(f);
    return ok;
}

// ── DownloadNetifyData ────────────────────────────────────────────────────────
// Mirrors nfa_task.cat_update from the Python agent:
//   - Downloads /lookup/applications (all pages)
//   - Downloads /lookup/application-categories
//   - Saves app-proto-data and category-index cache files
//   - Reloads the in-memory maps and config

void nfwaPlugin::DownloadNetifyData()
{
    nd_printf("%s: downloading app/category data from Netify API...\n",
        GetTag().c_str());

    json apps, cats;

    if (!FetchPaginated("/lookup/applications", apps)) {
        nd_printf("%s: warning: failed to download applications, keeping cached data\n",
            GetTag().c_str());
        return;
    }

    if (!FetchPaginated("/lookup/application_categories", cats)) {
        nd_printf("%s: warning: failed to download categories, keeping cached data\n",
            GetTag().c_str());
        return;
    }

    // Build app-proto-data (mirrors Python metadata dict)
    json app_proto;
    app_proto["application_tags"]         = json::object();
    app_proto["application_category_tags"] = json::object();

    for (const auto &app : apps) {
        if (!app.contains("id") || !app.contains("tag")) continue;
        if (!app.contains("application_category")) continue;

        nd_app_id_t id = app["id"].get<nd_app_id_t>();
        string tag     = app["tag"].get<string>();
        app_proto["application_tags"][tag] = id;
    }

    for (const auto &cat : cats) {
        if (!cat.contains("id") || !cat.contains("tag")) continue;
        string tag     = cat["tag"].get<string>();
        nd_cat_id_t id = cat["id"].get<nd_cat_id_t>();
        app_proto["application_category_tags"][tag] = id;
    }

    // Build category-index (mirrors Python category-index.json)
    json cat_index;
    cat_index["applications"] = json::object();

    for (const auto &app : apps) {
        if (!app.contains("id")) continue;
        if (!app.contains("application_category")) continue;

        nd_app_id_t id     = app["id"].get<nd_app_id_t>();
        nd_cat_id_t cat_id = app["application_category"]["id"].get<nd_cat_id_t>();
        cat_index["applications"][to_string(id)] = cat_id;
    }

    // Save to cache files
    try {
        ofstream fa(NFWA_CACHE_APPS);
        fa << app_proto.dump();
    } catch (...) {
        nd_printf("%s: warning: could not write %s\n", GetTag().c_str(), NFWA_CACHE_APPS);
    }
    try {
        ofstream fc(NFWA_CACHE_CATIDX);
        fc << cat_index.dump();
    } catch (...) {
        nd_printf("%s: warning: could not write %s\n", GetTag().c_str(), NFWA_CACHE_CATIDX);
    }

    nd_printf("%s: downloaded %zu apps, %zu categories\n",
        GetTag().c_str(), apps.size(), cats.size());

    // Reload maps and re-resolve config tags with fresh data
    Reload();
}

// ── LoadNetifyData ────────────────────────────────────────────────────────────
// Loads the cached app-proto-data and category-index files into the three
// in-memory maps.  Called at startup and after each DownloadNetifyData().

void nfwaPlugin::LoadNetifyData()
{
    unordered_map<string, nd_app_id_t> new_app_tag;
    unordered_map<nd_app_id_t, nd_cat_id_t> new_app_cat;
    unordered_map<string, nd_cat_id_t> new_cat_tag;

    // app-proto-data: application_tags and application_category_tags
    {
        ifstream f(NFWA_CACHE_APPS);
        if (f.is_open()) {
            try {
                auto j = json::parse(f);

                if (j.contains("application_tags")) {
                    for (auto &[tag, id] : j["application_tags"].items())
                        new_app_tag[tag] = id.get<nd_app_id_t>();
                }

                if (j.contains("application_category_tags")) {
                    for (auto &[tag, id] : j["application_category_tags"].items())
                        new_cat_tag[tag] = id.get<nd_cat_id_t>();
                }

                nd_printf("%s: loaded %zu app tags, %zu category tags from cache\n",
                    GetTag().c_str(), new_app_tag.size(), new_cat_tag.size());
            } catch (const exception &ex) {
                nd_printf("%s: warning: could not parse %s: %s\n",
                    GetTag().c_str(), NFWA_CACHE_APPS, ex.what());
            }
        }
    }

    // category-index: applications map  { "10228": 32, ... }
    {
        ifstream f(NFWA_CACHE_CATIDX);
        if (f.is_open()) {
            try {
                auto j = json::parse(f);

                if (j.contains("applications")) {
                    for (auto &[id_str, cat_id] : j["applications"].items()) {
                        nd_app_id_t app_id = (nd_app_id_t)stoul(id_str);
                        new_app_cat[app_id] = cat_id.get<nd_cat_id_t>();
                    }
                }

                nd_printf("%s: loaded %zu app→category entries from cache\n",
                    GetTag().c_str(), new_app_cat.size());
            } catch (const exception &ex) {
                nd_printf("%s: warning: could not parse %s: %s\n",
                    GetTag().c_str(), NFWA_CACHE_CATIDX, ex.what());
            }
        }
    }

    lock_guard<mutex> lg(config_mutex_);
    app_tag_to_id_ = move(new_app_tag);
    app_id_to_cat_ = move(new_app_cat);
    cat_tag_to_id_ = move(new_cat_tag);
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

            lock_guard<mutex> lg(config_mutex_);

            if (app_opt && app_opt->type == UCI_TYPE_STRING) {
                m.type = NfwaMapping::APP_TAG;
                m.key  = app_opt->v.string;
                auto it = app_tag_to_id_.find(m.key);
                if (it != app_tag_to_id_.end()) {
                    m.app_id = it->second;
                } else {
                    nd_printf("%s: warning: unknown application tag '%s' "
                              "(API data not yet downloaded?)\n",
                              GetTag().c_str(), m.key.c_str());
                }
                cfg.mappings.push_back(m);

            } else if (cat_opt && cat_opt->type == UCI_TYPE_STRING) {
                m.type = NfwaMapping::APP_CATEGORY;
                m.key  = cat_opt->v.string;
                auto it = cat_tag_to_id_.find(m.key);
                if (it != cat_tag_to_id_.end()) {
                    m.cat_id = it->second;
                } else {
                    nd_printf("%s: warning: unknown category tag '%s' "
                              "(API data not yet downloaded?)\n",
                              GetTag().c_str(), m.key.c_str());
                }
                cfg.mappings.push_back(m);
            }
        }
    }

    uci_free_context(ctx);

    {
        lock_guard<mutex> lg(config_mutex_);
        config_ = move(cfg);
    }

    nd_printf("%s: config loaded, %zu mappings, ttl=%us\n",
        GetTag().c_str(), config_.mappings.size(), config_.set_ttl);
}

// ── InitNftables ─────────────────────────────────────────────────────────────

void nfwaPlugin::InitNftables()
{
    const char *cmds =
        "add table inet sd_wrt\n"
        "add set inet sd_wrt sdwrt_interactive "
            "{ type ipv4_addr; flags timeout; }\n";

    if (nft_run_cmd_from_buffer(nft_ctx_, cmds) != 0)
        nd_printf("%s: warning: nftables init returned non-zero\n", GetTag().c_str());
}

// ── Entry ─────────────────────────────────────────────────────────────────────
// Background thread: mirrors nfa_cat_index_refresh from the Python agent.
// Downloads API data if the cache is missing or stale, then refreshes hourly.

void *nfwaPlugin::Entry(void)
{
    nd_printf("%s: started\n", GetTag().c_str());

    if (NeedsRefresh())
        DownloadNetifyData();

    // Check for refresh every hour, but wake every 60s to honour ShouldTerminate
    int ticks = 0;
    while (!ShouldTerminate()) {
        sleep(60);
        if (++ticks >= 60) {   // 60 × 60s = 1 hour
            ticks = 0;
            if (NeedsRefresh())
                DownloadNetifyData();
        }
    }

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
    nft_run_cmd_from_buffer(nft_ctx_, cmd);
}

// ── FindMatchingSet ────────────────────────────────────────────────────────────
// Mirrors flow_matches() from nfa_rule.py:
//   - Resolves the flow's numeric app_id → category using the downloaded
//     category-index (same as Python's config_cat_index['applications'])
//   - Matches against APP_TAG (exact app_id) or APP_CATEGORY (category_id)
// Returns {set_name, ttl} for the first matching rule, or {"", 0}.

pair<string, unsigned> nfwaPlugin::FindMatchingSet(const ndFlow *flow) const
{
    nd_app_id_t app_id = flow->detected_application;

    lock_guard<mutex> lg(config_mutex_);

    // Resolve app_id → category using the downloaded category-index.
    // This mirrors:  config_cat_index['applications'][str(app_id)]
    nd_cat_id_t app_cat = flow->category.application;
    if (app_cat == 0 && app_id != ND_APP_UNKNOWN) {
        auto it = app_id_to_cat_.find(app_id);
        if (it != app_id_to_cat_.end())
            app_cat = it->second;
    }

    // If no classification at all, nothing to match
    if (app_id == ND_APP_UNKNOWN && app_cat == 0)
        return {"", 0};

    for (const auto &m : config_.mappings) {
        bool matched = false;
        if (m.type == NfwaMapping::APP_TAG)
            matched = (m.app_id != ND_APP_UNKNOWN && app_id == m.app_id);
        else
            matched = (m.cat_id != 0 && app_cat == m.cat_id);

        if (matched)
            return {m.set, config_.set_ttl};
    }

    return {"", 0};
}

// ── ProcessFlow ──────────────────────────────────────────────────────────────
// Mirrors the flow processing loop in nfa_main.py / nfa_fw_iptables.process_flow:
//
//   - Only processes flows with a remote (internet) partner
//     → flow['other_type'] == 'remote'
//   - Only TCP, UDP, SCTP, UDPLite
//     → flow['ip_protocol'] in {6, 17, 132, 136}
//   - Skips DNS and MDNS
//     → flow['detected_protocol'] not in {5, 8}
//   - Determines the remote ("other") IP using lower_map
//     → mirrors the _lower_ip / _upper_ip swap in ndFlow::encode()
//   - Adds remote IP to the nftables set on NEW/UPDATED, removes on EXPIRING

void nfwaPlugin::ProcessFlow(ndDetectionEvent event, ndFlow *flow)
{
    // Only flows that have a remote (internet) partner
    if (flow->other_type != ndFlow::OTHER_REMOTE) return;

    // Only TCP (6), UDP (17), SCTP (132), UDPLite (136)
    if (flow->ip_protocol != 6  &&
        flow->ip_protocol != 17 &&
        flow->ip_protocol != 132 &&
        flow->ip_protocol != 136) return;

    // Skip DNS and MDNS — these are the resolver flows on the LAN, not
    // application traffic.  Mirrors the Python agent's filter.
    if (flow->detected_protocol == ND_PROTO_DNS ||
        flow->detected_protocol == ND_PROTO_MDNS) return;

    // Determine which address is the remote ("other") side.
    // ndFlow stores lower_addr and upper_addr in numeric order; lower_map
    // tells us which is the local (LAN) side.  This mirrors the
    // _lower_ip / _upper_ip assignment in ndFlow::encode().
    const ndAddr &other_addr = (flow->lower_map == ndFlow::LOWER_LOCAL)
        ? flow->upper_addr
        : flow->lower_addr;

    const string other_ip = other_addr.GetString();

    // sdwrt_interactive is ipv4_addr typed — skip IPv6 addresses
    if (other_ip.find(':') != string::npos) return;

    if (event == ndPluginDetection::EVENT_EXPIRING) {
        auto [set, ttl] = FindMatchingSet(flow);
        if (!set.empty())
            RemoveFromSet(set, other_ip);
        return;
    }

    if (event == ndPluginDetection::EVENT_NEW ||
        event == ndPluginDetection::EVENT_UPDATED) {
        auto [set, ttl] = FindMatchingSet(flow);
        if (!set.empty())
            AddToSet(set, other_ip, ttl);
    }
}

// ── Plugin factory ────────────────────────────────────────────────────────────

ndPluginInit(nfwaPlugin);
