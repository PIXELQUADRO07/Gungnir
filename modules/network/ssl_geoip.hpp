#ifndef SSL_GEOIP_HPP
#define SSL_GEOIP_HPP

#include <string>
#include <vector>

struct SslInfo {
    std::string subject;
    std::string issuer;
    std::string valid_from;
    std::string valid_until;
    std::vector<std::string> san;
    bool success = false;
};

struct GeoIpInfo {
    std::string ip;
    std::string country;
    std::string region;
    std::string city;
    std::string isp;
    std::string timezone;
    double lat = 0;
    double lon = 0;
    bool success = false;
};

// Extracts SSL certificate information from the target.
SslInfo get_ssl_info(const std::string& target, int port = 443);

// Performs GeoIP lookup for the given IP address.
GeoIpInfo get_geoip_info(const std::string& ip);

#endif
