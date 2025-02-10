#include "authenticator.h"
#include <stdexcept>
#include <sstream>
#include <curl/curl.h>
#include <curl/easy.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <thread>
#include <chrono>

using namespace std;
using namespace boost::property_tree;

#ifdef ENABLE_V2BOARD

namespace
{
    // Helper function for CURL write callback
    size_t write_callback(char *contents, size_t size, size_t nmemb, void *userp)
    {
        ((string *)userp)->append(contents, size * nmemb);
        return size * nmemb;
    }

    // Helper function to make CURL requests
    bool make_curl_request(const string &url, string &response, bool is_post = false, const string &post_data = "")
    {
        unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
        if (!curl)
        {
            Log::log_with_date_time("Failed to initialize CURL", Log::ERROR);
            return false;
        }

        struct curl_slist *headers = nullptr;
        if (is_post)
        {
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);
        }

        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10);
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 10);

        if (is_post)
        {
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, post_data.c_str());
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, post_data.size());
        }

        CURLcode res = curl_easy_perform(curl.get());
        if (headers)
            curl_slist_free_all(headers);

        if (res != CURLE_OK)
        {
            Log::log_with_date_time(string("CURL request failed: ") + curl_easy_strerror(res), Log::ERROR);
            return false;
        }
        return true;
    }
}

Authenticator::Authenticator(const Config &config)
{
    if (!config.v2board.enabled)
        throw runtime_error("V2Board authentication is not enabled in configuration");

    v2board.api_host = config.v2board.api_host;
    v2board.api_key = config.v2board.api_key;
    v2board.node_id = config.v2board.node_id;

    if (!fetch_user_list())
        throw runtime_error("Failed to fetch initial user list from V2Board");

    thread([this]()
    {
        while (true)
        {
            this_thread::sleep_for(chrono::minutes(3));
            Log::log_with_date_time("Updating user list from V2Board", Log::INFO);
            this->update_users();
            Log::log_with_date_time("Pushing traffic data to V2Board", Log::INFO);
            this->push_traffic();
        }
    }).detach();
}

bool Authenticator::auth(const string &password)
{
    lock_guard<mutex> lock(v2board.users_mutex);
    auto it = v2board.sha224_uuid_map.find(password);
    return it != v2board.sha224_uuid_map.end() && v2board.users_map.count(it->second);
}

bool Authenticator::record(const string &password, uint64_t download, uint64_t upload)
{
    string uuid;
    {
        lock_guard<mutex> users_lock(v2board.users_mutex);
        auto it = v2board.sha224_uuid_map.find(password);
        if (it == v2board.sha224_uuid_map.end()) return false;
        uuid = it->second;
    }

    // Log::log_with_date_time("Recording traffic for user: " + uuid + " download: " + to_string(download) + " upload: " + to_string(upload), Log::INFO);

    {
        lock_guard<mutex> stats_lock(v2board.stats_mutex);
        v2board.traffic_stats[uuid].first += download;
        v2board.traffic_stats[uuid].second += upload;
    }
    return true;
}

Authenticator::~Authenticator()
{
    push_traffic();
}

bool Authenticator::fetch_user_list()
{
    string url = v2board.api_host + "/api/v1/server/UniProxy/user?token=" + v2board.api_key +
                 "&node_id=" + to_string(v2board.node_id) + "&node_type=trojan";
    string response;

    if (!make_curl_request(url, response))
        return false;

    try
    {
        stringstream ss(response);
        ptree root;
        read_json(ss, root);

        if (!root.get_child_optional("users"))
        {
            Log::log_with_date_time("Invalid V2Board API response format", Log::ERROR);
            return false;
        }

        lock_guard<mutex> lock(v2board.users_mutex);
        v2board.users_map.clear();
        v2board.sha224_uuid_map.clear();

        for (const auto &user : root.get_child("users"))
        {
            string uuid = user.second.get<string>("uuid");
            uint32_t id = user.second.get<uint32_t>("id");
            v2board.users_map[uuid] = id;
            v2board.sha224_uuid_map[Config::SHA224(uuid)] = uuid;
        }

        Log::log_with_date_time("Fetched " + to_string(v2board.users_map.size()) + " users", Log::INFO);
        return true;
    }
    catch (const exception &e)
    {
        Log::log_with_date_time("Parse error: " + string(e.what()), Log::ERROR);
        return false;
    }
}

void Authenticator::update_users()
{
    if (!fetch_user_list())
    {
        Log::log_with_date_time("Failed to update user list from V2Board", Log::ERROR);
    }
}

void Authenticator::push_traffic()
{
    decltype(v2board.traffic_stats) traffic_stats_copy;
    {
        lock_guard<mutex> lock(v2board.stats_mutex);
        if (v2board.traffic_stats.empty()) return;
        traffic_stats_copy.swap(v2board.traffic_stats);
    }

    ptree data;
    {
        lock_guard<mutex> users_lock(v2board.users_mutex);
        for (const auto &[uuid, traffic] : traffic_stats_copy)
        {
            auto user_it = v2board.users_map.find(uuid);
            if (user_it == v2board.users_map.end()) continue;

            ptree traffic_array;
            traffic_array.push_back({"", ptree(to_string(traffic.first))});
            traffic_array.push_back({"", ptree(to_string(traffic.second))});
            data.put_child(to_string(user_it->second), traffic_array);
        }
    }

    stringstream ss;
    write_json(ss, data);
    string body = ss.str();

    string response;

    if (make_curl_request(v2board.api_host + "/api/v1/server/UniProxy/push?token=" + v2board.api_key +
                          "&node_id=" + to_string(v2board.node_id) + "&node_type=trojan",
                          response, true, body))
    {
        Log::log_with_date_time("Traffic pushed successfully", Log::INFO);
    }
    else
    {
        lock_guard<mutex> stats_lock(v2board.stats_mutex);
        for (const auto &[uuid, traffic] : traffic_stats_copy)
        {
            v2board.traffic_stats[uuid].first += traffic.first;
            v2board.traffic_stats[uuid].second += traffic.second;
        }
        Log::log_with_date_time("Failed to push traffic, data retained", Log::ERROR);
    }
}

#else // ENABLE_V2BOARD

Authenticator::Authenticator(const Config &) {}
bool Authenticator::auth(const string &) { return true; }
bool Authenticator::record(const string &, uint64_t, uint64_t) {}
Authenticator::~Authenticator() {}

#endif // ENABLE_V2BOARD
