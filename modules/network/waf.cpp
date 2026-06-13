#include "waf.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include <algorithm>
#include <map>

namespace {
    std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
}

WafResult detect_waf(const std::string& target) {
    WafResult result;
    result.target = target;

    // Ensure target has a protocol
    std::string url = target;
    if (url.find("http://") == std::string::npos && url.find("https://") == std::string::npos) {
        url = "http://" + url;
    }

    Logger::info("WAF: Analyzing " + url + "...");

    // 1. Passive check (headers from a normal request)
    HttpResponse resp = HttpClient::get(url);
    if (!resp.success) {
        Logger::error("WAF: Failed to connect to " + url);
        return result;
    }

    auto analyze_response = [&](const HttpResponse& r) {
        for (const auto& [key, value] : r.headers) {
            std::string k = to_lower(key);
            std::string v = to_lower(value);

            // Cloudflare
            if ((k == "server" && v.find("cloudflare") != std::string::npos) || 
                k.find("cf-ray") != std::string::npos || 
                k.find("cf-cache-status") != std::string::npos) {
                result.detected_waf = "Cloudflare";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // Akamai
            else if (k.find("x-akamai") != std::string::npos || 
                     (k == "server" && v.find("akamaighost") != std::string::npos)) {
                result.detected_waf = "Akamai";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // Imperva / Incapsula
            else if (k.find("x-incapsula") != std::string::npos || k.find("visid_incap") != std::string::npos || k == "x-cdn" && v.find("incapsula") != std::string::npos) {
                result.detected_waf = "Imperva / Incapsula";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // Sucuri
            else if (k.find("x-sucuri") != std::string::npos || (k == "server" && v.find("sucuri") != std::string::npos)) {
                result.detected_waf = "Sucuri";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // Amazon AWS WAF
            else if (k.find("x-amz-") != std::string::npos && (v.find("aws waf") != std::string::npos || v.find("awselb") != std::string::npos)) {
                result.detected_waf = "AWS WAF";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // F5 BIG-IP
            else if (k.find("x-wa-info") != std::string::npos || k.find("x-f5-") != std::string::npos) {
                result.detected_waf = "F5 BIG-IP ASM";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
            // FortiWeb
            else if (k.find("fortiwafsid") != std::string::npos) {
                result.detected_waf = "FortiWeb";
                result.found = true;
                result.evidence.push_back("Header found: " + key + ": " + value);
            }
        }
    };

    analyze_response(resp);
    if (result.found) return result;

    // 2. Active check (Send a payload that typically triggers WAFs)
    Logger::info("WAF: No passive signatures found. Trying active payload...");
    
    std::string malicious_url = url;
    if (malicious_url.find('?') == std::string::npos) {
        malicious_url += "/?id=' OR 1=1 --";
    } else {
        malicious_url += "&id=' OR 1=1 --";
    }

    HttpResponse active_resp = HttpClient::get(malicious_url);
    if (active_resp.status_code == 403 || active_resp.status_code == 406 || active_resp.status_code == 501) {
        analyze_response(active_resp);
        if (!result.found) {
            result.detected_waf = "Generic WAF / IPS (Blocked malicious payload)";
            result.found = true;
            result.evidence.push_back("Active payload triggered HTTP " + std::to_string(active_resp.status_code));
        }
    }

    return result;
}
