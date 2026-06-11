#ifndef ENGINE_HPP
#define ENGINE_HPP

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "network.hpp"
#include "scraper.hpp"
#include "recon.hpp"
#include "logger.hpp"
#include "../vendor/json.hpp"
using json = nlohmann::json;

// Kept for dump helpers that build JSON manually from non-scan data
namespace JsonUtil {
    inline std::string escape(const std::string& input) {
        std::string out;
        out.reserve(input.size());
        for (char c : input) {
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

struct ScanResult {
    std::string target;
    std::vector<PortInfo> ports;

    // Convenience: list of open port numbers
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

#include "database.hpp"

#include <functional>
#include <unordered_map>

class Engine {
public:
    Engine();

    bool execute(
        const std::string& mode,
        const std::string& target,
        const std::string& output_file = {},
        const std::vector<int>& ports = {}
    );

private:
    Database db;
    std::unordered_map<std::string, std::function<bool(const std::string&, const std::string&, const std::vector<int>&)>> executors;

    void register_executors();
    
    ScanResult run_scan(const std::string& target, const std::vector<int>& ports);
    bool run_scrape(const std::string& target);
    bool run_campaign(const std::string& target, const std::vector<int>& ports);
    bool run_dns(const std::string& target, const std::string& output_file);
    bool run_whois(const std::string& target, const std::string& output_file);
    bool run_history(const std::string& target);
    void print_scan_result(const ScanResult& result) const;
    void print_dns_result(const DnsResult& result) const;
    void print_whois_result(const WhoisResult& result) const;
    void print_threat_result(const std::string& target) const;
    bool dump_scan_result(const ScanResult& result, const std::string& output_file) const;
    bool dump_dns_result(const DnsResult& result, const std::string& output_file) const;
    bool dump_whois_result(const WhoisResult& result, const std::string& output_file) const;
    std::vector<int> default_scan_ports() const;
    bool is_ip_address(const std::string& target) const;
};

#endif
