#ifndef THREAT_INTEL_HPP
#define THREAT_INTEL_HPP

#include <string>
#include <vector>

struct ThreatIntelResult {
    bool success = false;
    std::string source; // "virustotal" or "shodan"
    
    // VT specific
    int malicious_votes = 0;
    
    // Shodan specific
    std::string isp;
    std::string country;
    std::vector<std::string> vulnerabilities;
    std::vector<int> known_ports;
};

class ThreatIntel {
public:
    static ThreatIntelResult query_virustotal(const std::string& target, const std::string& api_key);
    static ThreatIntelResult query_shodan(const std::string& ip, const std::string& api_key);
};

#endif
