#include "threat_intel.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "../../vendor/json.hpp"
#include <iostream>

using json = nlohmann::json;

ThreatIntelResult ThreatIntel::query_virustotal(const std::string& target, const std::string& api_key) {
    ThreatIntelResult res;
    res.source = "virustotal";

    if (api_key.empty()) {
        Logger::warn("VirusTotal API key non impostata.");
        return res;
    }

    const std::string url     = "https://www.virustotal.com/api/v3/domains/" + target;
    const std::map<std::string, std::string> headers = {{"x-apikey", api_key}};

    Logger::info("Interrogazione VirusTotal per: " + target);
    HttpResponse resp = HttpClient::get(url, headers, 12);

    if (resp.status_code == 200) {
        try {
            json j = json::parse(resp.body);
            res.malicious_votes = j.at("data")
                                   .at("attributes")
                                   .at("last_analysis_stats")
                                   .at("malicious")
                                   .get<int>();
            res.success = true;
        } catch (const json::exception& e) {
            Logger::warn("VirusTotal: parsing fallito — " + std::string(e.what()));
        }
    } else {
        Logger::error("VirusTotal API ha risposto con codice: " + std::to_string(resp.status_code));
    }

    return res;
}

ThreatIntelResult ThreatIntel::query_shodan(const std::string& ip, const std::string& api_key) {
    ThreatIntelResult res;
    res.source = "shodan";

    if (api_key.empty()) {
        Logger::warn("Shodan API key non impostata.");
        return res;
    }

    const std::string url = "https://api.shodan.io/shodan/host/" + ip + "?key=" + api_key;

    Logger::info("Interrogazione Shodan per: " + ip);
    HttpResponse resp = HttpClient::get(url, {}, 12);

    if (resp.status_code == 200) {
        try {
            json j = json::parse(resp.body);

            if (j.contains("isp"))          res.isp     = j["isp"].get<std::string>();
            if (j.contains("country_name")) res.country = j["country_name"].get<std::string>();

            if (j.contains("ports") && j["ports"].is_array()) {
                for (const auto& p : j["ports"]) {
                    if (p.is_number_integer())
                        res.known_ports.push_back(p.get<int>());
                }
            }

            if (j.contains("vulns") && j["vulns"].is_object()) {
                for (auto& [cve, _] : j["vulns"].items())
                    res.vulnerabilities.push_back(cve);
            }

            res.success = true;
        } catch (const json::exception& e) {
            Logger::warn("Shodan: parsing fallito — " + std::string(e.what()));
        }
    } else if (resp.status_code == 404) {
        Logger::warn("Nessun risultato trovato su Shodan per " + ip);
    } else {
        Logger::error("Shodan API ha risposto con codice: " + std::to_string(resp.status_code));
    }

    return res;
}

std::vector<BreachResult> ThreatIntel::query_breaches(const std::string& target) {
    std::vector<BreachResult> results;
    // Note: A real HIBP check requires an API key and per-email requests.
    // For now, this is a placeholder that demonstrates the module integration.
    Logger::info("Breach checking for: " + target);
    return results;
}
