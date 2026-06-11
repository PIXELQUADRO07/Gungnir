#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <string>
#include <vector>
#include "recon.hpp"

class Database {
public:
    Database(const std::string& db_path = "gungnir.db");
    ~Database();

    bool init();
    
    // Save scan results
    bool save_scan(const std::string& target, const std::vector<int>& open_ports);
    
    // Save DNS results
    bool save_dns(const std::string& target, const DnsResult& result);

private:
    void* db_handle; // Pointer to sqlite3 structure
};

#endif
