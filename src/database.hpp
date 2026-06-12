#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <string>
#include <vector>
#include "recon.hpp"

struct sqlite3;

// Returns the path to the user's data dir, creating it if needed (~/.gungnir/)
std::string get_gungnir_data_dir();

struct HistoryEntry {
    int id;
    std::string target;
    std::string timestamp;
    std::vector<int> ports;
};

struct ServiceInfo {
    int port;
    std::string protocol;
    std::string service;
    std::string product;
    std::string version;
    std::string banner;
    std::string cpe;
};

class Database {
public:
    Database();  // uses ~/.gungnir/data.db automatically
    explicit Database(const std::string& db_path);
    ~Database();

    bool init();

    // Save scan results
    bool save_scan(const std::string& target, const std::vector<int>& open_ports);

    // Save DNS results
    bool save_dns(const std::string& target, const DnsResult& result);

    // Save Service Info
    bool save_service(const std::string& target, const ServiceInfo& service);

    // History
    std::vector<HistoryEntry> get_history(const std::string& target = "");

    // Export Graph
    bool export_graph_json(const std::string& output_file);

    // Cache
    bool cache_set(const std::string& key, const std::string& value, int ttl_seconds);
    std::string cache_get(const std::string& key);

private:
    sqlite3* db_handle;
};

#endif
