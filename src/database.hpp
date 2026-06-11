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

    // History
    std::vector<HistoryEntry> get_history(const std::string& target = "");

    // Export Graph
    bool export_graph_json(const std::string& output_file);

private:
    sqlite3* db_handle;
};

#endif
