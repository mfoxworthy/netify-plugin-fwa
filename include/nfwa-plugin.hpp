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

constexpr unsigned _NFWA_PLUGIN_VER = 0x20260609;

// A single UCI mapping entry: app tag or category tag → nftables set name.
// For APP_CATEGORY, cat_id is resolved from the apps JSON at load time.
struct NfwaMapping {
    enum Type { APP_TAG, APP_CATEGORY } type;
    std::string key;       // e.g. "netify.zoom" or "voip-video" (tag string)
    std::string set;       // e.g. "sdwrt_interactive"
    nd_cat_id_t cat_id = 0; // resolved category id (APP_CATEGORY only)
};

struct NfwaConfig {
    unsigned set_ttl = 120;               // nftables element TTL in seconds
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
    // category tag → id map, loaded from netifyd apps JSON
    std::unordered_map<std::string, nd_cat_id_t> cat_tag_to_id_;

    struct nft_ctx *nft_ctx_ = nullptr;

    void Reload();
    void LoadConfig();
    void LoadCategoryMap();
    void InitNftables();

    // Returns the nftables set name if this flow matches a mapping, else "".
    std::string MatchMapping(const ndFlow *flow) const;

    void AddToSet(const std::string &set, const std::string &ip, unsigned ttl);
    void RemoveFromSet(const std::string &set, const std::string &ip);
};
