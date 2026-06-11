#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <map>
#include <string>
#include <vector>

struct PortInfo {
    int  port     = 0;
    bool open     = false;
    std::string banner;    // raw service banner (empty if none received)
    std::string service;   // guessed service name (e.g. "http", "ssh")
};

std::vector<PortInfo> start_native_scan(
    const std::string& target,
    const std::vector<int>& ports,
    int timeout_ms = 1000
);

// Helper: returns a known service name for well-known ports, or empty string
std::string guess_service(int port);

#endif
