#include "database.hpp"
#include "logger.hpp"
#include <sqlite3.h>
#include <iostream>

Database::Database(const std::string& db_path) : db_handle(nullptr) {
    if (sqlite3_open(db_path.c_str(), reinterpret_cast<sqlite3**>(&db_handle)) != SQLITE_OK) {
        Logger::error("Cannot open database: " + db_path);
        db_handle = nullptr;
    }
}

Database::~Database() {
    if (db_handle) {
        sqlite3_close(reinterpret_cast<sqlite3*>(db_handle));
    }
}

bool Database::init() {
    if (!db_handle) return false;
    
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS open_ports (
            scan_id INTEGER,
            port INTEGER,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

    char* err_msg = nullptr;
    if (sqlite3_exec(reinterpret_cast<sqlite3*>(db_handle), schema, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        Logger::error("SQL error on init: " + std::string(err_msg));
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool Database::save_scan(const std::string& target, const std::vector<int>& open_ports) {
    if (!db_handle) return false;
    sqlite3* db = reinterpret_cast<sqlite3*>(db_handle);
    
    // Insert scan
    const char* insert_scan = "INSERT INTO scans (target) VALUES (?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insert_scan, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    int scan_id = sqlite3_last_insert_rowid(db);
    
    // Insert ports
    const char* insert_port = "INSERT INTO open_ports (scan_id, port) VALUES (?, ?);";
    for (int port : open_ports) {
        if (sqlite3_prepare_v2(db, insert_port, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, scan_id);
            sqlite3_bind_int(stmt, 2, port);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    return true;
}

bool Database::save_dns(const std::string& target, const DnsResult& result) {
    if (!db_handle) return false;
    sqlite3* db = reinterpret_cast<sqlite3*>(db_handle);
    
    const char* insert_dns = "INSERT INTO dns_records (target, record_type, value) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    
    for (const auto& rec : result.records) {
        if (sqlite3_prepare_v2(db, insert_dns, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, rec.type.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, rec.value.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    for (const auto& sub : result.subdomains) {
        if (sqlite3_prepare_v2(db, insert_dns, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, "SUBDOMAIN", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, sub.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    return true;
}
