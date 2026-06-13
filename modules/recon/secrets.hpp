#ifndef SECRETS_HPP
#define SECRETS_HPP

#include <string>
#include <vector>

struct SecretMatch {
    std::string type;
    std::string value;
    std::string source_url;
};

struct SecretScanResult {
    std::string target;
    std::vector<SecretMatch> matches;
    std::vector<std::string> js_files;
    bool success = false;
};

// Scans target's JavaScript files for leaked secrets and API keys.
SecretScanResult run_secrets_scan(const std::string& target);

#endif
