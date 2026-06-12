#include "engine.hpp"
#include "logger.hpp"
#include "config.hpp"
#include "threat_intel.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

// ─── constructor ──────────────────────────────────────────────────────────────

Engine::Engine() {
    db.init();
    register_executors();
}

// ─── executor registry ────────────────────────────────────────────────────────

void Engine::register_executors() {

    executors["scan"] = [this](const std::string& target,
                               const std::string& output_file,
                               const std::vector<int>& ports) -> bool {
        const ScanResult res = run_scan(target, ports);
        print_scan_result(res);
        if (!output_file.empty()) dump_scan_result(res, output_file);
        return true;
    };

    executors["dns"] = [this](const std::string& target,
                              const std::string& output_file,
                              const std::vector<int>&) -> bool {
        return run_dns(target, output_file);
    };

    executors["whois"] = [this](const std::string& target,
                                const std::string& output_file,
                                const std::vector<int>&) -> bool {
        return run_whois(target, output_file);
    };

    executors["scrape"] = [this](const std::string& target,
                                 const std::string&,
                                 const std::vector<int>&) -> bool {
        return run_scrape(target);
    };

    executors["campaign"] = [this](const std::string& target,
                                   const std::string&,
                                   const std::vector<int>& ports) -> bool {
        return run_campaign(target, ports);
    };

    executors["threat"] = [this](const std::string& target,
                                 const std::string&,
                                 const std::vector<int>&) -> bool {
        print_threat_result(target);
        return true;
    };

    // history: target is optional (empty = show all)
    executors["history"] = [this](const std::string& target,
                                  const std::string&,
                                  const std::vector<int>&) -> bool {
        return run_history(target);
    };

    // graph: target is unused
    executors["graph"] = [this](const std::string&,
                                const std::string& output_file,
                                const std::vector<int>&) -> bool {
        const std::string out = output_file.empty() ? "graph.json" : output_file;
        return db.export_graph_json(out);
    };
}

// ─── dispatch ─────────────────────────────────────────────────────────────────

bool Engine::execute(
    const std::string& mode,
    const std::string& target,
    const std::string& output_file,
    const std::vector<int>& ports
) {
    auto it = executors.find(mode);
    if (it == executors.end()) {
        Logger::error("Unsupported mode: " + mode);
        return false;
    }
    return it->second(target, output_file, ports);
}

// ─── runners ──────────────────────────────────────────────────────────────────

ScanResult Engine::run_scan(const std::string& target, const std::vector<int>& ports) {
    const std::vector<int> scan_ports = ports.empty() ? default_scan_ports() : ports;

    std::ostringstream port_list;
    for (size_t i = 0; i < scan_ports.size(); ++i) {
        if (i) port_list << ", ";
        port_list << scan_ports[i];
    }
    Logger::info("Starting TCP scan on " + target +
                 "  [ports: " + port_list.str() + "]");

    const auto t0 = std::chrono::steady_clock::now();

    ScanResult result;
    result.target = target;
    result.ports  = start_native_scan(target, scan_ports, /*timeout_ms=*/1000);

    db.save_scan(target, result.open_port_numbers());

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    Logger::info("Scan completed in " + std::to_string(elapsed) + " ms");

    return result;
}

bool Engine::run_scrape(const std::string& target) {
    const ScrapeResult res = start_web_scrape(target);
    if (!res.success) return false;

    Logger::success("Scrape results for " + target);
    if (!res.title.empty())
        std::cout << "  - Title:  " << res.title << "\n";
    if (!res.server_header.empty())
        std::cout << "  - Server: " << res.server_header << "\n";
    if (!res.emails.empty()) {
        std::cout << "  - Emails found:\n";
        for (const auto& email : res.emails)
            std::cout << "      " << email << "\n";
    }
    return true;
}

bool Engine::run_campaign(const std::string& target, const std::vector<int>& ports) {
    Logger::info("Starting full OSINT campaign on " + target);

    const Config& cfg      = Config::instance();
    const bool    has_vt   = !cfg.get_vt_api_key().empty();
    const bool    has_shod = !cfg.get_shodan_api_key().empty();

    // Stage 1 — DNS
    Logger::info("[Stage 1/4] DNS enumeration");
    DnsResult dns_res = run_dns_lookup(target);
    db.save_dns(target, dns_res);
    print_dns_result(dns_res);

    // Collect all hosts to scan (target + discovered subdomains)
    std::vector<std::string> hosts = dns_res.subdomains;
    if (std::find(hosts.begin(), hosts.end(), target) == hosts.end())
        hosts.push_back(target);

    // Collect IPs for Shodan queries
    std::vector<std::string> ips;
    for (const auto& rec : dns_res.records)
        if (rec.type == "A" || rec.type == "AAAA")
            ips.push_back(rec.value);

    // Stage 2 — Port scan
    Logger::info("[Stage 2/4] Port scanning (" + std::to_string(hosts.size()) + " host(s))");
    std::vector<std::string> web_targets;
    for (const auto& host : hosts) {
        ScanResult sr = run_scan(host, ports);
        print_scan_result(sr);
        for (int p : sr.open_port_numbers()) {
            if (p == 80 || p == 443) {
                web_targets.push_back(
                    std::string(p == 443 ? "https://" : "http://") + host);
            }
        }
    }

    // Stage 3 — Web scraping
    Logger::info("[Stage 3/4] Web scraping (" +
                 std::to_string(web_targets.size()) + " endpoint(s))");
    for (const auto& url : web_targets)
        run_scrape(url);

    // Stage 4 — Threat intelligence
    if (has_vt || has_shod) {
        Logger::info("[Stage 4/4] Threat intelligence");
        if (has_vt)   print_threat_result(target);
        if (has_shod) for (const auto& ip : ips) print_threat_result(ip);
    } else {
        Logger::info("[Stage 4/4] Threat intelligence skipped — "
                     "no API keys configured (see ~/.gungnir.conf)");
    }

    Logger::success("Campaign completed for " + target);
    return true;
}

bool Engine::run_dns(const std::string& target, const std::string& output_file) {
    Logger::info("DNS lookup: " + target);
    const auto t0     = std::chrono::steady_clock::now();
    DnsResult  result = run_dns_lookup(target);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    db.save_dns(target, result);
    Logger::info("DNS lookup completed in " + std::to_string(elapsed) + " ms");
    print_dns_result(result);
    if (!output_file.empty()) return dump_dns_result(result, output_file);
    return result.success;
}

bool Engine::run_whois(const std::string& target, const std::string& output_file) {
    Logger::info("WHOIS query: " + target);
    const auto t0      = std::chrono::steady_clock::now();
    WhoisResult result = run_whois_lookup(target);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    Logger::info("WHOIS query completed in " + std::to_string(elapsed) + " ms");
    print_whois_result(result);
    if (!output_file.empty()) return dump_whois_result(result, output_file);
    return result.success;
}

bool Engine::run_history(const std::string& target) {
    const auto entries = db.get_history(target);
    if (entries.empty()) {
        Logger::info(target.empty()
            ? "No scans in local database."
            : "No scans found for " + target);
        return true;
    }

    Logger::success("Scan history" +
                    (target.empty() ? "" : " for " + target) +
                    " (" + std::to_string(entries.size()) + " entries):");

    for (const auto& e : entries) {
        std::cout << "  [" << e.timestamp << "]  " << e.target;
        if (!e.ports.empty()) {
            std::cout << "  open ports: ";
            for (size_t i = 0; i < e.ports.size(); ++i) {
                if (i) std::cout << ", ";
                std::cout << e.ports[i];
            }
        } else {
            std::cout << "  (no open ports)";
        }
        std::cout << "\n";
    }
    return true;
}

// ─── printers ─────────────────────────────────────────────────────────────────

void Engine::print_scan_result(const ScanResult& result) const {
    if (result.ports.empty()) {
        Logger::info("No open ports on " + result.target);
        return;
    }
    Logger::success("Open ports on " + result.target + ":");
    for (const auto& pi : result.ports) {
        std::string line = "  \033[32m" + std::to_string(pi.port) + "\033[0m";
        if (!pi.service.empty())
            line += "  \033[36m" + pi.service + "\033[0m";
        if (!pi.banner.empty()) {
            std::string first = pi.banner.substr(0, pi.banner.find('\n'));
            if (first.size() > 80) first = first.substr(0, 80) + "...";
            line += "  \"" + first + "\"";
        }
        Logger::result(line);
    }
}

void Engine::print_dns_result(const DnsResult& result) const {
    if (!result.success) {
        Logger::info("No DNS records found for " + result.target);
        return;
    }
    Logger::success("DNS records for " + result.target + ":");
    for (const auto& rec : result.records) {
        if (rec.type == "MX")
            std::cout << "  - MX (priority " << rec.priority << "): " << rec.value << "\n";
        else
            std::cout << "  - " << rec.type << ": " << rec.value << "\n";
    }
    if (!result.subdomains.empty()) {
        Logger::success("Subdomains found (" +
                        std::to_string(result.subdomains.size()) + "):");
        for (const auto& sub : result.subdomains)
            std::cout << "  - " << sub << "\n";
    }
}

void Engine::print_whois_result(const WhoisResult& result) const {
    if (!result.success) {
        Logger::info("No WHOIS data found for " + result.target);
        return;
    }
    Logger::success("WHOIS data for " + result.target +
                    "  (server: " + result.whois_server + "):");
    if (!result.registrar.empty())
        std::cout << "  - Registrar:   " << result.registrar     << "\n";
    if (!result.creation_date.empty())
        std::cout << "  - Created:     " << result.creation_date << "\n";
    if (!result.expiry_date.empty())
        std::cout << "  - Expires:     " << result.expiry_date   << "\n";
    if (!result.name_servers.empty()) {
        std::cout << "  - Name servers:\n";
        for (const auto& ns : result.name_servers)
            std::cout << "      " << ns << "\n";
    }

    std::cout << "\n  --- Raw Data ---\n";
    std::istringstream ss(result.raw_data);
    std::string line;
    int printed = 0;
    constexpr int MAX_LINES = 40;
    while (std::getline(ss, line) && printed < MAX_LINES) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '%' || line[0] == '#') continue;
        std::cout << "  " << line << "\n";
        ++printed;
    }
    if (printed == MAX_LINES)
        Logger::info("Output truncated. Use -o to save the full WHOIS response.");
}

void Engine::print_threat_result(const std::string& target) const {
    if (is_ip_address(target)) {
        const std::string key = Config::instance().get_shodan_api_key();
        if (key.empty()) {
            Logger::warn("Shodan API key missing — set SHODAN_API_KEY or add to ~/.gungnir.conf");
            return;
        }
        const ThreatIntelResult r = ThreatIntel::query_shodan(target, key);
        if (!r.success) return;
        Logger::success("Shodan intel for " + target);
        if (!r.isp.empty())     std::cout << "  - ISP:     " << r.isp     << "\n";
        if (!r.country.empty()) std::cout << "  - Country: " << r.country << "\n";
        if (!r.known_ports.empty()) {
            std::cout << "  - Ports:  ";
            for (size_t i = 0; i < r.known_ports.size(); ++i) {
                if (i) std::cout << ", ";
                std::cout << r.known_ports[i];
            }
            std::cout << "\n";
        }
        if (!r.vulnerabilities.empty()) {
            std::cout << "  - CVEs:\n";
            for (const auto& cve : r.vulnerabilities)
                std::cout << "      " << cve << "\n";
        }
    } else {
        const std::string key = Config::instance().get_vt_api_key();
        if (key.empty()) {
            Logger::warn("VirusTotal API key missing — set VT_API_KEY or add to ~/.gungnir.conf");
            return;
        }
        const ThreatIntelResult r = ThreatIntel::query_virustotal(target, key);
        if (!r.success) return;
        Logger::success("VirusTotal intel for " + target);
        const std::string verdict =
            r.malicious_votes == 0 ? "Clean" :
            r.malicious_votes < 5  ? "Suspicious" : "MALICIOUS";
        std::cout << "  - Malicious engines: " << r.malicious_votes
                  << "  [" << verdict << "]\n";
    }
}

// ─── serialisers ──────────────────────────────────────────────────────────────

bool Engine::dump_scan_result(const ScanResult& result, const std::string& path) const {
    std::ofstream out(path);
    if (!out) { Logger::error("Cannot open file for writing: " + path); return false; }
    out << result.to_json_string() << "\n";
    Logger::success("Scan result saved to " + path);
    return true;
}

bool Engine::dump_dns_result(const DnsResult& result, const std::string& path) const {
    std::ofstream out(path);
    if (!out) { Logger::error("Cannot open file for writing: " + path); return false; }

    std::ostringstream j;
    j << "{\n"
      << "  \"target\": \""    << JsonUtil::escape(result.target) << "\",\n"
      << "  \"records\": [";

    for (size_t i = 0; i < result.records.size(); ++i) {
        const auto& r = result.records[i];
        j << "\n    {\n"
          << "      \"type\": \""  << JsonUtil::escape(r.type)  << "\",\n"
          << "      \"value\": \"" << JsonUtil::escape(r.value) << "\"";
        if (r.priority >= 0)
            j << ",\n      \"priority\": " << r.priority;
        j << "\n    }";
        if (i + 1 < result.records.size()) j << ",";
    }

    j << "\n  ],\n  \"subdomains\": [";
    for (size_t i = 0; i < result.subdomains.size(); ++i) {
        j << "\n    \"" << JsonUtil::escape(result.subdomains[i]) << "\"";
        if (i + 1 < result.subdomains.size()) j << ",";
    }
    j << "\n  ]\n}";

    out << j.str() << "\n";
    Logger::success("DNS result saved to " + path);
    return true;
}

bool Engine::dump_whois_result(const WhoisResult& result, const std::string& path) const {
    std::ofstream out(path);
    if (!out) { Logger::error("Cannot open file for writing: " + path); return false; }

    // Split raw_data into lines → JSON array (readable, not an escaped blob)
    std::vector<std::string> lines;
    {
        std::istringstream ss(result.raw_data);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
        }
    }

    std::ostringstream j;
    j << "{\n"
      << "  \"target\": \""        << JsonUtil::escape(result.target)        << "\",\n"
      << "  \"whois_server\": \""  << JsonUtil::escape(result.whois_server)  << "\",\n"
      << "  \"registrar\": \""     << JsonUtil::escape(result.registrar)     << "\",\n"
      << "  \"creation_date\": \"" << JsonUtil::escape(result.creation_date) << "\",\n"
      << "  \"expiry_date\": \""   << JsonUtil::escape(result.expiry_date)   << "\",\n"
      << "  \"name_servers\": [";
    for (size_t i = 0; i < result.name_servers.size(); ++i) {
        j << "\"" << JsonUtil::escape(result.name_servers[i]) << "\"";
        if (i + 1 < result.name_servers.size()) j << ", ";
    }
    j << "],\n  \"raw_data\": [\n";
    for (size_t i = 0; i < lines.size(); ++i) {
        j << "    \"" << JsonUtil::escape(lines[i]) << "\"";
        if (i + 1 < lines.size()) j << ",";
        j << "\n";
    }
    j << "  ]\n}";

    out << j.str() << "\n";
    Logger::success("WHOIS result saved to " + path);
    return true;
}

// ─── utilities ────────────────────────────────────────────────────────────────

std::vector<int> Engine::default_scan_ports() const {
    return {21, 22, 23, 25, 53, 80, 110, 143, 443,
            465, 587, 993, 995, 1433, 3306, 3389,
            5432, 5900, 6379, 8080, 8443, 27017};
}

bool Engine::is_ip_address(const std::string& target) const {
    if (target.find(':') != std::string::npos) return true;  // IPv6
    bool has_dot = false;
    for (const char c : target) {
        if (c == '.') { has_dot = true; continue; }
        if (!isdigit(static_cast<unsigned char>(c))) return false;
    }
    return has_dot;
}
