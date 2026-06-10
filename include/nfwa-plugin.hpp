// netify-plugin-fwa — firewall agent plugin (netifyd 4.4.7 API)
#pragma once

// STL — must precede netifyd headers (they use bare identifiers)
#include <map>
#include <mutex>
#include <string>
#include <vector>

// System
#include <signal.h>
#include <stdint.h>

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

// A single UCI mapping entry: app tag or category tag → nftables set name
struct NfwaMapping {
    enum Type { APP_TAG, APP_CATEGORY } type;
    std::string key;  // e.g. "netify.zoom" or "voip-video"
    std::string set;  // e.g. "sdwrt_interactive"
};

struct NfwaConfig {
    unsigned set_ttl = 120;               // nftables element TTL in seconds
    std::vector<NfwaMapping> mappings;
};

class nfwaPlugin : public ndPluginDetection {
public:
    explicit nfwaPlugin(const std::string &tag);
    ~nfwaPlugin();

    void Reload() override;
    void Entry() override;

    void ProcessFlow(
        ndPlugin::ndPluginFlowMap *flow_map,
        ndFlow *flow,
        ndpi_protocol &proto,
        bool new_flow
    ) override;

private:
    std::mutex config_mutex_;
    NfwaConfig config_;

    struct nft_ctx *nft_ctx_ = nullptr;

    void LoadConfig();
    void InitNftables();

    // Returns the nftables set name if this flow matches a mapping, else "".
    std::string MatchMapping(const ndFlow *flow) const;

    void AddToSet(const std::string &set, const std::string &ip, unsigned ttl);
    void RemoveFromSet(const std::string &set, const std::string &ip);
};

extern "C" ndPlugin *CreatePlugin(const std::string &tag) {
    return new nfwaPlugin(tag);
}
