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
    {
        throw runtime_error("V2Board authentication is not enabled in configuration");
    }
    v2board.api_host = config.v2board.api_host;
    v2board.api_key = config.v2board.api_key;
    v2board.node_id = config.v2board.node_id;

    if (!fetch_user_list())
    {
        throw runtime_error("Failed to fetch initial user list from V2Board");
    }

    // Start a background thread to periodically update users and push traffic data
    thread([this]()
           {
        while (true) {
            Log::log_with_date_time("Updating user list from V2Board", Log::INFO);
            this->update_users();
            Log::log_with_date_time("Pushing traffic data to V2Board", Log::INFO);
            this->push_traffic();
            this_thread::sleep_for(chrono::minutes(3));
        } })
        .detach();
}

bool Authenticator::auth(const string &password)
{
    lock_guard<mutex> lock(v2board.users_mutex);
    auto it = v2board.sha224_uuid_map.find(password);
    if (it == v2board.sha224_uuid_map.end())
    {
        return false;
    }
    return v2board.users_map.find(it->second) != v2board.users_map.end();
}

void Authenticator::record(const string &password, uint64_t download, uint64_t upload)
{
    lock_guard<mutex> users_lock(v2board.users_mutex);
    auto it = v2board.sha224_uuid_map.find(password);
    if (it == v2board.sha224_uuid_map.end())
    {
        return;
    }

    lock_guard<mutex> stats_lock(v2board.stats_mutex);
    auto &entry = v2board.traffic_stats[it->second];
    entry.first += download;
    entry.second += upload;
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
    {
        return false;
    }

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

        Log::log_with_date_time("Fetched " + to_string(v2board.users_map.size()) + " users from V2Board", Log::INFO);
        return true;
    }
    catch (const exception &e)
    {
        Log::log_with_date_time("Failed to parse V2Board API response: " + string(e.what()), Log::ERROR);
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
        if (v2board.traffic_stats.empty())
        {
            return;
        }
        traffic_stats_copy = v2board.traffic_stats;
        v2board.traffic_stats.clear();
    }

    ptree data;
    for (const auto &stats_pair : traffic_stats_copy)
    {
        ptree traffic_array;
        traffic_array.push_back(make_pair("", ptree(to_string(stats_pair.second.first))));
        traffic_array.push_back(make_pair("", ptree(to_string(stats_pair.second.second))));
        data.put_child(stats_pair.first, traffic_array);
    }

    stringstream ss;
    write_json(ss, data);
    string body = ss.str();

    string url = v2board.api_host + "/api/v1/server/UniProxy/push?token=" + v2board.api_key +
                 "&node_id=" + to_string(v2board.node_id) + "&node_type=trojan";
    string response;

    if (make_curl_request(url, response, true, body))
    {
        Log::log_with_date_time("Traffic data pushed successfully", Log::INFO);
    }
    else
    {
        Log::log_with_date_time("Failed to push traffic data", Log::ERROR);
        lock_guard<mutex> lock(v2board.stats_mutex);
        for (const auto &stats_pair : traffic_stats_copy)
        {
            auto &entry = v2board.traffic_stats[stats_pair.first];
            entry.first += stats_pair.second.first;
            entry.second += stats_pair.second.second;
        }
    }
}

#else // ENABLE_V2BOARD

Authenticator::Authenticator(const Config &) {}
bool Authenticator::auth(const string &) { return true; }
void Authenticator::record(const string &, uint64_t, uint64_t) {}
Authenticator::~Authenticator() {}

#endif // ENABLE_V2BOARD
