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
    std::vector<int> open_ports;

    std::string to_json_string() const {
        std::ostringstream out;
        out << "{\n"
            << "  \"target\": \"" << JsonUtil::escape(target) << "\",\n"
            << "  \"open_ports\": [";

        for (size_t i = 0; i < open_ports.size(); ++i) {
            out << open_ports[i];
            if (i + 1 < open_ports.size()) {
                out << ", ";
            }
        }

        out << "]\n}";
        return out.str();
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
