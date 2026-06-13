#include "secrets.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include <regex>
#include <set>
#include <algorithm>

namespace {
    struct SecretSignature {
        std::string name;
        std::string regex_pattern;
    };

    const std::vector<SecretSignature> signatures = {
        {"Google API Key", R"(AIza[0-9A-Za-z-_]{35})"},
        {"AWS Access Key ID", R"(AKIA[0-9A-Z]{16})"},
        {"AWS Secret", R"(aws_secret_access_key\s*[:=]\s*['"]?([0-9a-zA-Z/+=]{40})['"]?)"},
        {"Slack Webhook", R"(https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)"},
        {"Stripe API Key", R"(sk_live_[0-9a-zA-Z]{24})"},
        {"Mailgun API Key", R"(key-[0-9a-zA-Z]{32})"},
        {"GitHub Token", R"(ghp_[0-9a-zA-Z]{36})"},
        {"Discord Webhook", R"(https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)"},
        {"Private Key", R"(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----)"},
        {"Generic Secret", R"(["'](?:api_key|apikey|secret|token|auth)["']\s*[:=]\s*["']([a-zA-Z0-9_-]{16,})["'])"},
        {"Firebase URL", R"(https://[a-z0-9-]+\.firebaseio\.com)"},
        {"Internal Endpoint", R"(/api/v[0-9]/[a-zA-Z0-9_-]+)"}
    };

    std::string resolve_url(const std::string& base, const std::string& path) {
        if (path.find("http") == 0) return path;
        
        std::string result = base;
        if (result.back() == '/') result.pop_back();
        
        if (path.empty()) return result;
        if (path[0] == '/') return result + path;
        return result + "/" + path;
    }
}

SecretScanResult run_secrets_scan(const std::string& target) {
    SecretScanResult result;
    result.target = target;
    
    std::string url = target;
    if (url.find("http") != 0) url = "http://" + url;

    Logger::info("Secrets Scanner: Fetching main page " + url + "...");
    HttpResponse resp = HttpClient::get(url);
    if (!resp.success) {
        Logger::error("Secrets Scanner: Failed to connect to " + url);
        return result;
    }

    result.success = true;
    std::set<std::string> js_urls;

    // Extract JS files
    std::regex js_regex(R"(src=["']([^"']+\.js(\?[^"']*)?)["'])", std::regex_constants::icase);
    auto js_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), js_regex);
    auto js_end = std::sregex_iterator();
    for (std::sregex_iterator i = js_begin; i != js_end; ++i) {
        js_urls.insert(resolve_url(url, (*i)[1].str()));
    }

    Logger::info("Secrets Scanner: Found " + std::to_string(js_urls.size()) + " JS files. Analyzing...");

    for (const auto& js_url : js_urls) {
        result.js_files.push_back(js_url);
        HttpResponse js_resp = HttpClient::get(js_url);
        if (js_resp.success) {
            for (const auto& sig : signatures) {
                std::regex re(sig.regex_pattern, std::regex_constants::icase);
                auto match_begin = std::sregex_iterator(js_resp.body.begin(), js_resp.body.end(), re);
                auto match_end = std::sregex_iterator();
                for (std::sregex_iterator i = match_begin; i != match_end; ++i) {
                    SecretMatch m;
                    m.type = sig.name;
                    m.value = (*i).str();
                    m.source_url = js_url;
                    
                    // Avoid duplicates
                    bool exists = false;
                    for (const auto& existing : result.matches) {
                        if (existing.value == m.value && existing.type == m.type) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) result.matches.push_back(m);
                }
            }
        }
    }

    return result;
}
