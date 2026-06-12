#pragma once

#include <sstream>
#include <string>
#include <vector>
#include "logger.hpp"

// ─── version ──────────────────────────────────────────────────────────────────

inline constexpr const char* GUNGNIR_VERSION     = "Gungnir v1.2.0 (C++20)";
inline constexpr const char* GUNGNIR_VERSION_NUM = "1.2.0";
inline constexpr const char* GUNGNIR_REPO_OWNER  = "PIXELQUADRO07";
inline constexpr const char* GUNGNIR_REPO_NAME   = "Gungnir";

// ─── parse_ports ──────────────────────────────────────────────────────────────
// Parses a comma-separated port string (e.g. "22,80,443") into a vector<int>.
// Invalid or out-of-range values are warned and skipped.

inline std::vector<int> parse_ports(const std::string& ports_arg) {
    std::vector<int> results;
    std::istringstream ss(ports_arg);
    std::string token;
    while (std::getline(ss, token, ',')) {
        const auto b = token.find_first_not_of(" \t");
        const auto e = token.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        const std::string p = token.substr(b, e - b + 1);
        try {
            const int port = std::stoi(p);
            if (port > 0 && port <= 65535)
                results.push_back(port);
            else
                Logger::warn("Port out of range, skipped: " + p);
        } catch (...) {
            Logger::warn("Invalid port value, skipped: " + p);
        }
    }
    return results;
}

// ─── tokenize ─────────────────────────────────────────────────────────────────
// Splits a shell-like line into tokens with support for single/double quoting:
//   scan example.com -o "my output.json"  →  ["scan","example.com","-o","my output.json"]

inline std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> tokens;
    std::string current;
    char in_quote = 0;

    for (const char c : line) {
        if (in_quote) {
            if (c == in_quote) in_quote = 0;
            else               current += c;
            continue;
        }
        if (c == '\'' || c == '"') { in_quote = c; continue; }
        if (c == ' '  || c == '\t') {
            if (!current.empty()) { tokens.push_back(current); current.clear(); }
            continue;
        }
        current += c;
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

// ─── parse_args ───────────────────────────────────────────────────────────────
// Scans tokens[from..] for -p and -o flags.
// The target is the first non-flag token. Warns on unknown flags.

struct ParsedArgs {
    std::string      target;
    std::vector<int> ports;
    std::string      output_file;
};

inline ParsedArgs parse_args(
    const std::vector<std::string>& tokens,
    size_t from,
    bool ports_supported = true
) {
    ParsedArgs result;
    for (size_t i = from; i < tokens.size(); ++i) {
        const std::string& t = tokens[i];

        if (t == "-p") {
            if (!ports_supported) {
                Logger::warn("Flag -p ignored: this command does not use ports.");
                if (i + 1 < tokens.size()) ++i;
                continue;
            }
            if (i + 1 >= tokens.size()) {
                Logger::warn("Flag -p requires a value (e.g. -p 80,443).");
                continue;
            }
            result.ports = parse_ports(tokens[++i]);

        } else if (t == "-o") {
            if (i + 1 >= tokens.size()) {
                Logger::warn("Flag -o requires a value (e.g. -o output.json).");
                continue;
            }
            result.output_file = tokens[++i];

        } else if (t == "-n" || t == "--no-update" ||
                   t == "-q" || t == "--quiet") {
            // global flags already handled in main(); safe to skip here

        } else if (!t.empty() && t[0] == '-') {
            Logger::warn("Unknown flag ignored: " + t + ". Type 'help' for the list.");

        } else if (result.target.empty()) {
            result.target = t;

        } else {
            Logger::warn("Extra argument ignored: " + t);
        }
    }
    return result;
}
