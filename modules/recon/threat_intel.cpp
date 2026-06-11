#include "threat_intel.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include <regex>
#include <iostream>

ThreatIntelResult ThreatIntel::query_virustotal(const std::string& target, const std::string& api_key) {
    ThreatIntelResult res;
    res.source = "virustotal";
    
    if (api_key.empty()) {
        Logger::warn("VirusTotal API key non impostata.");
        return res;
    }

    std::string url = "https://www.virustotal.com/api/v3/domains/" + target;
    std::map<std::string, std::string> headers = {
        {"x-apikey", api_key}
    };
    
    Logger::info("Interrogazione VirusTotal per: " + target);
    HttpResponse resp = HttpClient::get(url, headers);
    
    if (resp.status_code == 200) {
        res.success = true;
        std::regex mal_regex(R"REGEX("malicious"\s*:\s*(\d+))REGEX");
        std::smatch match;
        if (std::regex_search(resp.body, match, mal_regex) && match.size() > 1) {
            res.malicious_votes = std::stoi(match[1].str());
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
    
    std::string url = "https://api.shodan.io/shodan/host/" + ip + "?key=" + api_key;
    
    Logger::info("Interrogazione Shodan per: " + ip);
    HttpResponse resp = HttpClient::get(url);
    
    if (resp.status_code == 200) {
        res.success = true;
        
        std::regex isp_regex(R"REGEX("isp"\s*:\s*"([^"]+)")REGEX");
        std::smatch match;
        if (std::regex_search(resp.body, match, isp_regex) && match.size() > 1) {
            res.isp = match[1].str();
        }
        
        std::regex country_regex(R"REGEX("country_name"\s*:\s*"([^"]+)")REGEX");
        if (std::regex_search(resp.body, match, country_regex) && match.size() > 1) {
            res.country = match[1].str();
        }
        
        std::regex ports_regex(R"REGEX("ports"\s*:\s*\[([^\]]*)\])REGEX");
        if (std::regex_search(resp.body, match, ports_regex) && match.size() > 1) {
            std::string ports_str = match[1].str();
            std::regex num_regex(R"(\d+)");
            auto words_begin = std::sregex_iterator(ports_str.begin(), ports_str.end(), num_regex);
            auto words_end = std::sregex_iterator();
            for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                res.known_ports.push_back(std::stoi((*i).str()));
            }
        }
        
        std::regex vulns_regex(R"REGEX("vulns"\s*:\s*\[([^\]]*)\])REGEX");
        if (std::regex_search(resp.body, match, vulns_regex) && match.size() > 1) {
            std::string vulns_str = match[1].str();
            std::regex cve_regex(R"REGEX("([^"]+)")REGEX");
            auto words_begin = std::sregex_iterator(vulns_str.begin(), vulns_str.end(), cve_regex);
            auto words_end = std::sregex_iterator();
            for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                res.vulnerabilities.push_back((*i)[1].str());
            }
        }
    } else if (resp.status_code == 404) {
        Logger::warn("Nessun risultato trovato su Shodan per " + ip);
    } else {
        Logger::error("Shodan API ha risposto con codice: " + std::to_string(resp.status_code));
    }
    
    return res;
}
