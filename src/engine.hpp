#ifndef ENGINE_HPP
#define ENGINE_HPP

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "network.hpp"
#include "scraper.hpp"
#include "recon.hpp"
#include "logger.hpp"
#include "database.hpp"
#include "../vendor/json.hpp"

using json = nlohmann::json;

// ─── JSON escape helper ───────────────────────────────────────────────────────

namespace JsonUtil {
    inline std::string escape(const std::string& input) {
        std::string out;
        out.reserve(input.size());
        for (const char c : input) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        return out;
    }
}

// ─── ScanResult ───────────────────────────────────────────────────────────────

struct ScanResult {
    std::string target;
    std::vector<PortInfo> ports;

    std::vector<int> open_port_numbers() const {
        std::vector<int> v;
        v.reserve(ports.size());
        for (const auto& p : ports) v.push_back(p.port);
        return v;
    }

    std::string to_json_string() const {
        json j;
        j["target"] = target;
        json arr = json::array();
        for (const auto& pi : ports) {
            json entry;
            entry["port"]    = pi.port;
            entry["service"] = pi.service;
            if (!pi.banner.empty()) entry["banner"] = pi.banner;
            arr.push_back(entry);
        }
        j["open_ports"] = arr;
        return j.dump(2);
    }
};

// ─── Engine ───────────────────────────────────────────────────────────────────

class Engine {
public:
    Engine();

    bool execute(
        const std::string& mode,
        const std::string& target,
        const std::string& output_file = {},
        const std::vector<int>& ports  = {}
    );

private:
    using ExecutorFn = std::function<bool(
        const std::string& target,
        const std::string& output_file,
        const std::vector<int>& ports
    )>;

    Database db;
    std::unordered_map<std::string, ExecutorFn> executors;

    void register_executors();

    // ── runners ───────────────────────────────────────────────────────────────
    ScanResult run_scan   (const std::string& target, const std::vector<int>& ports);
    bool       run_scrape (const std::string& target);
    bool       run_campaign(const std::string& target, const std::vector<int>& ports);
    bool       run_dns    (const std::string& target, const std::string& output_file);
    bool       run_whois  (const std::string& target, const std::string& output_file);
    bool       run_history(const std::string& target);

    // ── printers ──────────────────────────────────────────────────────────────
    void print_scan_result  (const ScanResult&  result) const;
    void print_dns_result   (const DnsResult&   result) const;
    void print_whois_result (const WhoisResult& result) const;
    void print_threat_result(const std::string& target) const;

    // ── serialisers ───────────────────────────────────────────────────────────
    bool dump_scan_result  (const ScanResult&  result, const std::string& output_file) const;
    bool dump_dns_result   (const DnsResult&   result, const std::string& output_file) const;
    bool dump_whois_result (const WhoisResult& result, const std::string& output_file) const;

    // ── utilities ─────────────────────────────────────────────────────────────
    std::vector<int> default_scan_ports() const;
    bool             is_ip_address(const std::string& target) const;
};

#endif
