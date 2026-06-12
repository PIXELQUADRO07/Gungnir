#include "database.hpp"
#include "logger.hpp"
#include <sqlite3.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

// ─── helpers ──────────────────────────────────────────────────────────────────

std::string get_gungnir_data_dir() {
    const char* home = std::getenv("HOME");
    if (!home) home = getpwuid(getuid())->pw_dir;
    std::string dir = std::string(home) + "/.gungnir";
    mkdir(dir.c_str(), 0700);
    return dir;
}

// ─── constructors ─────────────────────────────────────────────────────────────

Database::Database() : Database(get_gungnir_data_dir() + "/data.db") {}

Database::Database(const std::string& db_path) : db_handle(nullptr) {
    if (sqlite3_open(db_path.c_str(), &db_handle) != SQLITE_OK) {
        std::string err = db_handle ? sqlite3_errmsg(db_handle) : "Memory allocation failed";
        Logger::error("Cannot open database: " + db_path + " (" + err + ")");
        db_handle = nullptr;
    }
}

Database::~Database() {
    if (db_handle) {
        sqlite3_close(db_handle);
    }
}

// ─── init ─────────────────────────────────────────────────────────────────────

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
        CREATE TABLE IF NOT EXISTS services (
            target TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            banner TEXT,
            cpe TEXT,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(target, port, protocol)
        );
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT,
            expires_at DATETIME
        );
    )";

    char* err_msg = nullptr;
    if (sqlite3_exec(db_handle, schema, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "Unknown error";
        Logger::error("SQL error on init: " + err);
        if (err_msg) sqlite3_free(err_msg);
        return false;
    }
    return true;
}

// ─── save_scan ────────────────────────────────────────────────────────────────

bool Database::save_scan(const std::string& target, const std::vector<int>& open_ports) {
    if (!db_handle) return false;

    const char* insert_scan = "INSERT INTO scans (target) VALUES (?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_handle, insert_scan, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_int64 scan_id = sqlite3_last_insert_rowid(db_handle);

    const char* insert_port = "INSERT INTO open_ports (scan_id, port) VALUES (?, ?);";
    for (int port : open_ports) {
        if (sqlite3_prepare_v2(db_handle, insert_port, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, scan_id);
            sqlite3_bind_int(stmt, 2, port);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    return true;
}

// ─── save_dns ─────────────────────────────────────────────────────────────────

bool Database::save_dns(const std::string& target, const DnsResult& result) {
    if (!db_handle) return false;

    const char* insert_dns = "INSERT INTO dns_records (target, record_type, value) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;

    for (const auto& rec : result.records) {
        if (sqlite3_prepare_v2(db_handle, insert_dns, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, rec.type.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, rec.value.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    for (const auto& sub : result.subdomains) {
        if (sqlite3_prepare_v2(db_handle, insert_dns, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, "SUBDOMAIN", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, sub.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return true;
}

// ─── save_service ─────────────────────────────────────────────────────────────

bool Database::save_service(const std::string& target, const ServiceInfo& s) {
    if (!db_handle) return false;

    const char* sql = R"(
        INSERT OR REPLACE INTO services 
        (target, port, protocol, service, product, version, banner, cpe) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_handle, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, s.port);
    sqlite3_bind_text(stmt, 3, s.protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, s.service.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, s.product.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, s.version.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, s.banner.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, s.cpe.c_str(),      -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

// ─── get_history ──────────────────────────────────────────────────────────────

std::vector<HistoryEntry> Database::get_history(const std::string& target) {
    std::vector<HistoryEntry> entries;
    if (!db_handle) return entries;

    std::string query;
    sqlite3_stmt* stmt;

    if (target.empty()) {
        query = "SELECT id, target, timestamp FROM scans ORDER BY timestamp DESC LIMIT 50;";
        sqlite3_prepare_v2(db_handle, query.c_str(), -1, &stmt, nullptr);
    } else {
        query = "SELECT id, target, timestamp FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 50;";
        sqlite3_prepare_v2(db_handle, query.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        HistoryEntry e;
        e.id        = sqlite3_column_int(stmt, 0);
        e.target    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entries.push_back(e);
    }
    sqlite3_finalize(stmt);

    // Fill ports for each entry
    for (auto& e : entries) {
        const char* ports_q = "SELECT port FROM open_ports WHERE scan_id = ?;";
        sqlite3_stmt* ps;
        if (sqlite3_prepare_v2(db_handle, ports_q, -1, &ps, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(ps, 1, e.id);
            while (sqlite3_step(ps) == SQLITE_ROW) {
                e.ports.push_back(sqlite3_column_int(ps, 0));
            }
            sqlite3_finalize(ps);
        }
    }

    return entries;
}

std::vector<ServiceInfo> Database::get_services(const std::string& target) {
    std::vector<ServiceInfo> services;
    if (!db_handle) return services;

    const char* sql = "SELECT port, protocol, service, product, version, banner, cpe FROM services WHERE target = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db_handle, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        Logger::error("SQL error prepare get_services: " + std::string(sqlite3_errmsg(db_handle)));
        return services;
    }

    sqlite3_bind_text(stmt, 1, target.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ServiceInfo s;
        s.port     = sqlite3_column_int(stmt, 0);
        s.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        s.service  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        s.product  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        s.version  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        s.banner   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        s.cpe      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        services.push_back(s);
    }
    sqlite3_finalize(stmt);
    return services;
}

// ─── export_graph_json ────────────────────────────────────────────────────────

bool Database::export_graph_json(const std::string& output_file) {
    if (!db_handle) return false;

    std::ofstream out(output_file);
    if (!out.is_open()) return false;

    out << "{\n  \"nodes\": [\n";

    std::string q_nodes = R"(
        SELECT DISTINCT target AS id, 'domain' AS type FROM dns_records
        UNION
        SELECT DISTINCT value AS id, 'ip' AS type FROM dns_records WHERE record_type = 'A' OR record_type = 'AAAA'
        UNION
        SELECT DISTINCT target AS id, 'domain' AS type FROM scans
        UNION
        SELECT DISTINCT CAST(port AS TEXT) AS id, 'port' AS type FROM open_ports
    )";

    sqlite3_stmt* stmt;
    bool first = true;
    if (sqlite3_prepare_v2(db_handle, q_nodes.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) out << ",\n";
            std::string id   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            out << "    { \"id\": \"" << id << "\", \"type\": \"" << type << "\" }";
            first = false;
        }
        sqlite3_finalize(stmt);
    }

    out << "\n  ],\n  \"edges\": [\n";

    first = true;

    std::string q_edges_dns = "SELECT target, value, record_type FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME');";
    if (sqlite3_prepare_v2(db_handle, q_edges_dns.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) out << ",\n";
            std::string source   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string target_v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string label    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            out << "    { \"source\": \"" << source << "\", \"target\": \"" << target_v << "\", \"label\": \"" << label << "\" }";
            first = false;
        }
        sqlite3_finalize(stmt);
    }

    std::string q_edges_ports = "SELECT s.target, CAST(p.port AS TEXT) FROM scans s JOIN open_ports p ON s.id = p.scan_id;";
    if (sqlite3_prepare_v2(db_handle, q_edges_ports.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) out << ",\n";
            std::string source   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string target_v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            out << "    { \"source\": \"" << source << "\", \"target\": \"" << target_v << "\", \"label\": \"has_open_port\" }";
            first = false;
        }
        sqlite3_finalize(stmt);
    }

    out << "\n  ]\n}\n";

    Logger::success("Grafo esportato in: " + output_file);
    return true;
}

// ─── cache ────────────────────────────────────────────────────────────────────

bool Database::cache_set(const std::string& key, const std::string& value, int ttl_seconds) {
    if (!db_handle) return false;

    const char* sql = "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, datetime('now', ?));";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_handle, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    std::string ttl_str = "+" + std::to_string(ttl_seconds) + " seconds";
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ttl_str.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::string Database::cache_get(const std::string& key) {
    if (!db_handle) return "";

    const char* sql = "SELECT value FROM cache WHERE key = ? AND expires_at > datetime('now');";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_handle, sql, -1, &stmt, nullptr) != SQLITE_OK) return "";

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string res;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        res = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    return res;
}
