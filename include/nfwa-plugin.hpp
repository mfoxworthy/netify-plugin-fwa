// netify-plugin-fwa — firewall agent plugin (netifyd 4.4.7 API)
#pragma once

// STL — must precede all netifyd 4.4.7 headers; they use bare identifiers
// and rely on these being in scope.
#include <atomic>
#include <bitset>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// System
#include <dlfcn.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// pcap (required by nd-*.h)
#include <pcap/pcap.h>

// Third-party bundled with netifyd
#include <nlohmann/json.hpp>
#include <radix/radix_tree.hpp>

using namespace std;
using json = nlohmann::json;

// netifyd headers — exact order confirmed working in netify-plugin-stats
#include <netifyd.h>
#include <nd-sha1.h>
#include <nd-ndpi.h>
#include <nd-thread.h>
#include <nd-risks.h>
#include <nd-serializer.h>
#include <nd-packet.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-addr.h>
#include <nd-apps.h>
#include <nd-protos.h>
#include <nd-category.h>
#include <nd-flow.h>
#include <nd-flow-map.h>
#include <nd-plugin.h>

constexpr unsigned _NFWA_PLUGIN_VER = 0x20260612;

// Netify API base URL and cache paths
#define NFWA_API_BASE      "https://api.netify.ai/api/v1"
#define NFWA_CACHE_APPS    "/etc/netify.d/netify-fwa-app-proto.json"
#define NFWA_CACHE_CATIDX  "/etc/netify.d/netify-fwa-cat-index.json"
#define NFWA_CACHE_TTL     86400  // 24 hours, matching Python agent

// A single UCI mapping entry: application tag or category tag → nftables set name.
// app_id and cat_id are resolved from the downloaded Netify API data at load time.
struct NfwaMapping {
    enum Type { APP_TAG, APP_CATEGORY } type;
    std::string key;                    // original tag string (for logging)
    std::string set;                    // nftables set name
    nd_app_id_t app_id = ND_APP_UNKNOWN; // resolved for APP_TAG
    nd_cat_id_t cat_id = 0;              // resolved for APP_CATEGORY
};

struct NfwaConfig {
    unsigned set_ttl = 120;
    std::vector<NfwaMapping> mappings;
};

class nfwaPlugin : public ndPluginDetection {
public:
    explicit nfwaPlugin(const std::string &tag);
    ~nfwaPlugin();

    virtual void *Entry(void) override;
    virtual void ProcessFlow(ndDetectionEvent event, ndFlow *flow) override;
    virtual void GetVersion(string &version) override;

private:
    mutable std::mutex config_mutex_;
    NfwaConfig config_;

    // Maps populated from Netify API data (same data as Python agent's
    // app-proto-data.json and category-index.json)
    std::unordered_map<std::string, nd_app_id_t> app_tag_to_id_;  // "netify.zoom" → 10228
    std::unordered_map<nd_app_id_t, nd_cat_id_t> app_id_to_cat_;  // 10228 → 32
    std::unordered_map<std::string, nd_cat_id_t> cat_tag_to_id_;  // "voip" → 32

    struct nft_ctx *nft_ctx_ = nullptr;

    void Reload();
    void LoadConfig();
    void LoadNetifyData();
    bool NeedsRefresh() const;
    bool FetchPage(const std::string &url, json &result);
    bool FetchPaginated(const std::string &endpoint, json &items);
    void DownloadNetifyData();
    void InitNftables();

    // Returns {set_name, ttl} for the first matching mapping, or {"", 0}.
    // Mirrors flow_matches() + process_flow() logic from the Python agent.
    std::pair<std::string, unsigned> FindMatchingSet(const ndFlow *flow) const;

    void AddToSet(const std::string &set, const std::string &ip, unsigned ttl);
    void RemoveFromSet(const std::string &set, const std::string &ip);
};
