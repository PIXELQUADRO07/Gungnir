#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <string>
#include <vector>

std::vector<int> start_native_scan(
    const std::string& target,
    const std::vector<int>& ports,
    int timeout_ms = 1000
);

#endif
