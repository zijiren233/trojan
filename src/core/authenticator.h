#ifndef _AUTHENTICATOR_H_
#define _AUTHENTICATOR_H_

#include "config.h"

#ifdef ENABLE_V2BOARD
#include <string>
#include <mutex>
#include <unordered_map>
#endif

class Authenticator {
private:
#ifdef ENABLE_V2BOARD
    struct V2Board {
        std::string api_host;
        std::string api_key;
        uint32_t node_id;
        // uuid -> id
        std::unordered_map<std::string, uint32_t> users_map;
        // sha224(uuid) -> uuid
        std::unordered_map<std::string, std::string> sha224_uuid_map;
        // uuid -> traffic stats
        std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> traffic_stats;
        std::mutex users_mutex;
        std::mutex stats_mutex;
    } v2board;

    void update_users();
    void push_traffic();
    bool fetch_user_list();
#endif

public:
    explicit Authenticator(const Config &config);
    bool auth(const std::string &password);
    void record(const std::string &password, uint64_t download, uint64_t upload);
    ~Authenticator();
};

#endif // _AUTHENTICATOR_H_
