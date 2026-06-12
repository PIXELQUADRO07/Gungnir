#ifndef THREAT_INTEL_HPP
#define THREAT_INTEL_HPP

#include <string>
#include <vector>

struct ThreatIntelResult {
    bool success = false;
    std::string source; // "virustotal", "shodan", or "breach"
    
    // VT specific
    int malicious_votes = 0;
    
    // Shodan specific
    std::string isp;
    std::string country;
    std::vector<std::string> vulnerabilities;
    std::vector<int> known_ports;
};

struct BreachResult {
    std::string email;
    std::vector<std::string> breaches;
    bool leaked = false;
};

class ThreatIntel {
public:
    static ThreatIntelResult query_virustotal(const std::string& target, const std::string& api_key);
    static ThreatIntelResult query_shodan(const std::string& ip, const std::string& api_key);
    static std::vector<BreachResult> query_breaches(const std::string& target);
};

#endif
