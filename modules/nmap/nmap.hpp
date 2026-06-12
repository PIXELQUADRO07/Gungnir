#pragma once

#include <string>
#include <vector>

// ─── data structures ──────────────────────────────────────────────────────────

struct NmapPort {
    int         port     = 0;
    std::string protocol;   // "tcp" / "udp"
    std::string state;      // "open" / "filtered" / "closed"
    std::string service;    // e.g. "http", "ssh"
    std::string product;
    std::string version;    // banner / version string if detected
    std::string cpe;
};

struct NmapHost {
    std::string          ip;
    std::string          hostname;
    std::string          os_guess;
    std::vector<NmapPort> ports;
};

struct NmapResult {
    bool                    success  = false;
    std::string             raw;        // full nmap stdout (kept for -o dump)
    std::vector<NmapHost>   hosts;
    std::string             error;
};

// ─── public API ───────────────────────────────────────────────────────────────

// Checks whether nmap is available on PATH. Returns its path or empty string.
std::string nmap_find();

// Runs nmap on target with extra_args appended.
// Parses stdout into structured NmapResult.
NmapResult nmap_scan(
    const std::string&              target,
    const std::vector<std::string>& extra_args = {},
    const std::vector<int>&         ports      = {}
);
