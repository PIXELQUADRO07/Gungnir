#pragma once

#include <sstream>
#include <string>
#include <vector>
#include "logger.hpp"

// ─── version ──────────────────────────────────────────────────────────────────

inline constexpr const char* GUNGNIR_VERSION = "Gungnir v1.0.0-Alpha (C++20)";

// ─── parse_ports ──────────────────────────────────────────────────────────────
// Parses a comma-separated port string (e.g. "22,80,443") into a vector<int>.
// Invalid or out-of-range values are warned and skipped.

inline std::vector<int> parse_ports(const std::string& ports_arg) {
    std::vector<int> results;
    std::istringstream ss(ports_arg);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // trim whitespace around each token
        const auto b = token.find_first_not_of(" \t");
        const auto e = token.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        const std::string p = token.substr(b, e - b + 1);
        try {
            const int port = std::stoi(p);
            if (port > 0 && port <= 65535)
                results.push_back(port);
            else
                Logger::warn("Port out of range ignored: " + p);
        } catch (...) {
            Logger::warn("Invalid port ignored: " + p);
        }
    }
    return results;
}

// ─── tokenize ─────────────────────────────────────────────────────────────────
// Splits a shell-like line into tokens. Supports single and double quoted
// strings so that paths with spaces work correctly:
//   scan example.com -o "my output.json"  →  ["scan","example.com","-o","my output.json"]

inline std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> tokens;
    std::string current;
    char in_quote = 0;

    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];

        if (in_quote) {
            if (c == in_quote) {
                in_quote = 0;           // closing quote
            } else {
                current += c;
            }
            continue;
        }

        if (c == '\'' || c == '"') {
            in_quote = c;               // opening quote
            continue;
        }

        if (c == ' ' || c == '\t') {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }

        current += c;
    }

    if (!current.empty())
        tokens.push_back(current);

    return tokens;
}

// ─── parse_flags ──────────────────────────────────────────────────────────────
// Scans tokens[from..] for -p and -o flags.
// The target is the first non-flag token; returns it (or empty if not found).
// Warns on unknown flags.

struct ParsedArgs {
    std::string target;
    std::vector<int> ports;
    std::string output_file;
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
                Logger::warn("Flag -p ignored: this command does not support ports.");
                if (i + 1 < tokens.size()) ++i;  // consume value anyway
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
        } else if (t[0] == '-') {
            Logger::warn("Unknown flag ignored: " + t + ". Type 'help' for the list.");
        } else if (result.target.empty()) {
            result.target = t;
        } else {
            Logger::warn("Argomento extra ignorato: " + t);
        }
    }
    return result;
}
