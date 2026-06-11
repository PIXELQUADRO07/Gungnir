#include "engine.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <numeric>
#include <sstream>

bool Engine::execute(
    const std::string& mode,
    const std::string& target,
    const std::string& output_file,
    const std::vector<int>& ports
) {
    if (mode == "scan") {
        const ScanResult result = run_scan(target, ports);
        print_scan_result(result);

        if (!output_file.empty()) {
            return dump_scan_result(result, output_file);
        }

        return true;
    }

    if (mode == "scrape") {
        return run_scrape(target);
    }

    if (mode == "dns") {
        return run_dns(target, output_file);
    }

    if (mode == "whois") {
        return run_whois(target, output_file);
    }

    Logger::error("Invalid mode specified: " + mode);
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

    const auto end_time = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    Logger::info("Scan completed in " + std::to_string(elapsed_ms) + " ms");

    return result;
}

bool Engine::run_scrape(const std::string& target) {
    Logger::info("Executing OSINT scraping on " + target);
    Logger::warn("The scrape module is currently a stub; only placeholder logs are available.");
    start_web_scrape(target);
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
}

void Engine::print_whois_result(const WhoisResult& result) const {
    if (!result.success) {
        Logger::info("No WHOIS data found for " + result.target);
        return;
    }

    Logger::success("WHOIS data for " + result.target + " (server: " + result.whois_server + "):");

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
