#ifndef WAF_HPP
#define WAF_HPP

#include <string>
#include <vector>

struct WafResult {
    std::string target;
    std::string detected_waf;
    bool found = false;
    std::vector<std::string> evidence;
};

// Detects if a target is protected by a WAF (Web Application Firewall).
WafResult detect_waf(const std::string& target);

#endif
