#include "engine.hpp"
#include "logger.hpp"
#include "config.hpp"
#include "threat_intel.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <numeric>
#include <sstream>

Engine::Engine() {
    db.init();
    register_executors();
}

void Engine::register_executors() {
    executors["scan"] = [this](const std::string& target, const std::string& output_file, const std::vector<int>& ports) -> bool {
        const std::vector<int> scan_ports = ports.empty() ? default_scan_ports() : ports;
        ScanResult res = run_scan(target, scan_ports);
        print_scan_result(res);
        if (!output_file.empty()) dump_scan_result(res, output_file);
        return true;
    };

    executors["scrape"] = [this](const std::string& target, const std::string& /*output_file*/, const std::vector<int>& /*ports*/) -> bool {
        return run_scrape(target);
    };

    executors["campaign"] = [this](const std::string& target, const std::string& /*output_file*/, const std::vector<int>& ports) -> bool {
        return run_campaign(target, ports);
    };

    executors["dns"] = [this](const std::string& target, const std::string& output_file, const std::vector<int>& /*ports*/) -> bool {
        return run_dns(target, output_file);
    };

    executors["whois"] = [this](const std::string& target, const std::string& output_file, const std::vector<int>& /*ports*/) -> bool {
        return run_whois(target, output_file);
    };

    executors["threat"] = [this](const std::string& target, const std::string& /*output_file*/, const std::vector<int>& /*ports*/) -> bool {
        print_threat_result(target);
        return true;
    };

    executors["graph"] = [this](const std::string& /*target*/, const std::string& output_file, const std::vector<int>& /*ports*/) -> bool {
        std::string out = output_file.empty() ? "graph.json" : output_file;
        return db.export_graph_json(out);
    };

    executors["history"] = [this](const std::string& target, const std::string& /*output_file*/, const std::vector<int>& /*ports*/) -> bool {
        return run_history(target == "dummy" ? "" : target);
    };
}

bool Engine::execute(
    const std::string& mode,
    const std::string& target,
    const std::string& output_file,
    const std::vector<int>& ports
) {
    auto it = executors.find(mode);
    if (it != executors.end()) {
        return it->second(target, output_file, ports);
    }
    
    Logger::error("Modalità non supportata: " + mode);
    return false;
}

ScanResult Engine::run_scan(
    const std::string& target,
    const std::vector<int>& ports
) {
    Logger::info("Starting TCP scan on " + target);
    const std::vector<int> scan_ports = ports.empty() ? default_scan_ports() : ports;

    std::ostringstream port_list;
    for (size_t i = 0; i < scan_ports.size(); ++i) {
        if (i) port_list << ", ";
        port_list << scan_ports[i];
    }
    Logger::info("Porte da scansionare: " + port_list.str());

    const auto start_time = std::chrono::steady_clock::now();

    ScanResult result;
    result.target = target;
    result.open_ports = start_native_scan(target, scan_ports, 1000);
    
    db.save_scan(target, result.open_ports);

    const auto end_time = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    Logger::info("Scan completed in " + std::to_string(elapsed_ms) + " ms");

    return result;
}

bool Engine::run_scrape(const std::string& target) {
    ScrapeResult res = start_web_scrape(target);
    if (!res.success) return false;

    Logger::success("Scrape results for " + target);
    if (!res.title.empty()) std::cout << "  - Title: " << res.title << "\n";
    if (!res.server_header.empty()) std::cout << "  - Server: " << res.server_header << "\n";
    if (!res.emails.empty()) {
        std::cout << "  - Emails found:\n";
        for (const auto& email : res.emails) {
            std::cout << "      " << email << "\n";
        }
    }
    return true;
}

bool Engine::run_campaign(const std::string& target, const std::vector<int>& ports) {
    Logger::info("Starting Campaign on " + target);

    const Config& cfg = Config::instance();
    const bool has_vt     = !cfg.get_vt_api_key().empty();
    const bool has_shodan = !cfg.get_shodan_api_key().empty();

    // 1. DNS
    Logger::info("[Stage 1] DNS Enumeration");
    DnsResult dns_res = run_dns_lookup(target);
    db.save_dns(target, dns_res);
    print_dns_result(dns_res);

    std::vector<std::string> hosts_to_scan = dns_res.subdomains;
    if (std::find(hosts_to_scan.begin(), hosts_to_scan.end(), target) == hosts_to_scan.end())
        hosts_to_scan.push_back(target);

    // Collect IPs for threat intel
    std::vector<std::string> discovered_ips;
    for (const auto& rec : dns_res.records)
        if (rec.type == "A" || rec.type == "AAAA")
            discovered_ips.push_back(rec.value);

    // 2. Port Scan
    Logger::info("[Stage 2] Port Scanning");
    std::vector<std::string> web_targets;
    for (const auto& host : hosts_to_scan) {
        ScanResult sres = run_scan(host, ports);
        print_scan_result(sres);
        for (int p : sres.open_ports) {
            if (p == 80 || p == 443) {
                std::string proto = (p == 443) ? "https://" : "http://";
                web_targets.push_back(proto + host + ":" + std::to_string(p));
            }
        }
    }

    // 3. Web Scraper
    Logger::info("[Stage 3] Web Scraping");
    for (const auto& web_t : web_targets)
        run_scrape(web_t);

    // 4. Threat Intelligence (auto, if keys set)
    if (has_vt || has_shodan) {
        Logger::info("[Stage 4] Threat Intelligence");
        if (has_vt)
            print_threat_result(target);  // domain → VirusTotal
        if (has_shodan) {
            for (const auto& ip : discovered_ips)
                print_threat_result(ip);  // each IP → Shodan
        }
    } else {
        Logger::info("[Stage 4] Threat Intel skipped — no API keys (see ~/.gungnir.conf)");
    }

    Logger::success("Campaign completed for " + target);
    return true;
}

void Engine::print_scan_result(const ScanResult& result) const {
    if (result.open_ports.empty()) {
        Logger::info("No open ports detected on " + result.target);
        return;
    }

    Logger::success("Open ports on " + result.target + ":");
    for (int port : result.open_ports) {
        std::cout << "  - " << port << "\n";
    }
}

bool Engine::is_ip_address(const std::string& target) const {
    // Accepts dotted IPv4 (1.2.3.4) or IPv6 (contains ':')
    if (target.find(':') != std::string::npos) return true;
    bool has_dot = false;
    for (char c : target) {
        if (c == '.') { has_dot = true; continue; }
        if (!isdigit(static_cast<unsigned char>(c))) return false;
    }
    return has_dot;
}

void Engine::print_threat_result(const std::string& target) const {
    if (is_ip_address(target)) {
        const std::string key = Config::instance().get_shodan_api_key();
        if (key.empty()) {
            Logger::warn("Shodan API key mancante — imposta SHODAN_API_KEY o aggiungi a ~/.gungnir.conf");
            return;
        }
        ThreatIntelResult r = ThreatIntel::query_shodan(target, key);
        if (!r.success) return;
        Logger::success("Shodan intel per " + target);
        if (!r.isp.empty())     std::cout << "  - ISP:     " << r.isp << "\n";
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
            Logger::warn("VirusTotal API key mancante — imposta VT_API_KEY o aggiungi a ~/.gungnir.conf");
            return;
        }
        ThreatIntelResult r = ThreatIntel::query_virustotal(target, key);
        if (!r.success) return;
        Logger::success("VirusTotal intel per " + target);
        std::string verdict = (r.malicious_votes == 0) ? "Clean" :
                              (r.malicious_votes < 5)  ? "Suspicious" : "MALICIOUS";
        std::cout << "  - Malicious engines: " << r.malicious_votes
                  << "  [" << verdict << "]\n";
    }
}

bool Engine::run_history(const std::string& target) {
    auto entries = db.get_history(target);
    if (entries.empty()) {
        Logger::info(target.empty() ? "Nessuna scansione nel DB locale."
                                    : "Nessuna scansione per " + target);
        return true;
    }

    Logger::success("Storico scan" + (target.empty() ? "" : " per " + target) +
                    " (" + std::to_string(entries.size()) + " voci):");
    for (const auto& e : entries) {
        std::cout << "  [" << e.timestamp << "]  " << e.target;
        if (!e.ports.empty()) {
            std::cout << "  ports: ";
            for (size_t i = 0; i < e.ports.size(); ++i) {
                if (i) std::cout << ",";
                std::cout << e.ports[i];
            }
        } else {
            std::cout << "  (no open ports)";
        }
        std::cout << "\n";
    }
    return true;
}

bool Engine::dump_scan_result(
    const ScanResult& result,
    const std::string& output_file
) const {
    std::ofstream out(output_file);
    if (!out) {
        Logger::error("Unable to open output file: " + output_file);
        return false;
    }

    out << result.to_json_string() << std::endl;
    Logger::success("Result saved to " + output_file);
    return true;
}

std::vector<int> Engine::default_scan_ports() const {
    return {22, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017};
}

bool Engine::run_dns(const std::string& target, const std::string& output_file) {
    Logger::info("Executing DNS lookup on " + target);

    const auto start_time = std::chrono::steady_clock::now();
    const DnsResult result = run_dns_lookup(target);
    db.save_dns(target, result);
    const auto end_time = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    Logger::info("DNS lookup completed in " + std::to_string(elapsed_ms) + " ms");

    print_dns_result(result);

    if (!output_file.empty()) {
        return dump_dns_result(result, output_file);
    }

    return result.success;
}

bool Engine::run_whois(const std::string& target, const std::string& output_file) {
    Logger::info("Executing WHOIS query on " + target);

    const auto start_time = std::chrono::steady_clock::now();
    const WhoisResult result = run_whois_lookup(target);
    const auto end_time = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    Logger::info("WHOIS query completed in " + std::to_string(elapsed_ms) + " ms");

    print_whois_result(result);

    if (!output_file.empty()) {
        return dump_whois_result(result, output_file);
    }

    return result.success;
}

void Engine::print_dns_result(const DnsResult& result) const {
    if (!result.success) {
        Logger::info("No DNS records found for " + result.target);
        return;
    }

    Logger::success("DNS records for " + result.target + ":");
    for (const auto& record : result.records) {
        if (record.type == "MX") {
            std::cout << "  - MX (priorita " << record.priority << "): " << record.value << "\n";
        } else {
            std::cout << "  - " << record.type << ": " << record.value << "\n";
        }
    }

    if (!result.subdomains.empty()) {
        Logger::success("Subdomains found (" + std::to_string(result.subdomains.size()) + "):");
        for (const auto& sub : result.subdomains) {
            std::cout << "  - " << sub << "\n";
        }
    }
}

void Engine::print_whois_result(const WhoisResult& result) const {
    if (!result.success) {
        Logger::info("No WHOIS data found for " + result.target);
        return;
    }

    Logger::success("WHOIS data for " + result.target + " (server: " + result.whois_server + "):");

    if (!result.registrar.empty()) std::cout << "  - Registrar: " << result.registrar << "\n";
    if (!result.creation_date.empty()) std::cout << "  - Created: " << result.creation_date << "\n";
    if (!result.expiry_date.empty()) std::cout << "  - Expires: " << result.expiry_date << "\n";
    if (!result.name_servers.empty()) {
        std::cout << "  - Name Servers:\n";
        for (const auto& ns : result.name_servers) {
            std::cout << "      " << ns << "\n";
        }
    }
    std::cout << "\n  --- Raw Data ---\n";

    std::istringstream stream(result.raw_data);
    std::string line;
    int printed = 0;
    constexpr int max_lines = 40;

    while (std::getline(stream, line) && printed < max_lines) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty() || line[0] == '%' || line[0] == '#') {
            continue;
        }
        std::cout << "  " << line << "\n";
        ++printed;
    }

    if (printed == max_lines) {
        Logger::info("Output truncated. Use -o to save the full WHOIS response.");
    }
}

bool Engine::dump_dns_result(const DnsResult& result, const std::string& output_file) const {
    std::ofstream out(output_file);
    if (!out) {
        Logger::error("Unable to open output file: " + output_file);
        return false;
    }

    std::ostringstream json;
    json << "{\n"
         << "  \"target\": \"" << JsonUtil::escape(result.target) << "\",\n"
         << "  \"records\": [";

    for (size_t i = 0; i < result.records.size(); ++i) {
        const auto& record = result.records[i];
        json << "\n    {\n"
             << "      \"type\": \"" << JsonUtil::escape(record.type) << "\",\n"
             << "      \"value\": \"" << JsonUtil::escape(record.value) << "\"";

        if (record.priority >= 0) {
            json << ",\n      \"priority\": " << record.priority;
        }

        json << "\n    }";
        if (i + 1 < result.records.size()) {
            json << ",";
        }
    }

    json << "\n  ],\n"
         << "  \"subdomains\": [";

    for (size_t i = 0; i < result.subdomains.size(); ++i) {
        json << "\n    \"" << JsonUtil::escape(result.subdomains[i]) << "\"";
        if (i + 1 < result.subdomains.size()) {
            json << ",";
        }
    }

    json << "\n  ]\n}";

    out << json.str() << std::endl;
    Logger::success("DNS result saved to " + output_file);
    return true;
}

bool Engine::dump_whois_result(const WhoisResult& result, const std::string& output_file) const {
    std::ofstream out(output_file);
    if (!out) {
        Logger::error("Unable to open output file: " + output_file);
        return false;
    }

    // Split raw_data into lines and store as a JSON array — far more readable
    // than a single escaped string with \n sequences.
    std::vector<std::string> lines;
    {
        std::istringstream ss(result.raw_data);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
        }
    }

    std::ostringstream json;
    json << "{\n"
         << "  \"target\": \""       << JsonUtil::escape(result.target)       << "\",\n"
         << "  \"whois_server\": \"" << JsonUtil::escape(result.whois_server) << "\",\n"
         << "  \"registrar\": \"" << JsonUtil::escape(result.registrar) << "\",\n"
         << "  \"creation_date\": \"" << JsonUtil::escape(result.creation_date) << "\",\n"
         << "  \"expiry_date\": \"" << JsonUtil::escape(result.expiry_date) << "\",\n"
         << "  \"name_servers\": [";
         
    for (size_t i = 0; i < result.name_servers.size(); ++i) {
        json << "\"" << JsonUtil::escape(result.name_servers[i]) << "\"";
        if (i + 1 < result.name_servers.size()) json << ", ";
    }

    json << "],\n"
         << "  \"raw_data\": [\n";

    for (size_t i = 0; i < lines.size(); ++i) {
        json << "    \"" << JsonUtil::escape(lines[i]) << "\"";
        if (i + 1 < lines.size()) json << ",";
        json << "\n";
    }

    json << "  ]\n}";

    out << json.str() << "\n";
    Logger::success("WHOIS result saved to " + output_file);
    return true;
}
