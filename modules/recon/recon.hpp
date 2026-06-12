#ifndef RECON_HPP
#define RECON_HPP

#include <string>
#include <vector>

struct DnsRecord {
    std::string type;   // A, AAAA, MX, NS, TXT, CNAME, SOA
    std::string value;
    int priority = -1;  // used for MX records, -1 if not applicable
};

struct DnsResult {
    std::string target;
    std::vector<DnsRecord> records;
    std::vector<std::string> subdomains;
    bool success = false;
};

struct WhoisResult {
    std::string target;
    std::string raw_data;
    std::string whois_server;
    
    // Structured fields
    std::string registrar;
    std::string creation_date;
    std::string expiry_date;
    std::vector<std::string> name_servers;

    bool success = false;
};

struct TakeoverResult {
    std::string subdomain;
    std::string cname;
    std::string provider;
    bool vulnerable = false;
};

// Performs DNS lookups for A, AAAA, MX, NS, TXT and CNAME records.
DnsResult run_dns_lookup(const std::string& target);

// Checks if a subdomain is vulnerable to takeover based on its CNAME record.
TakeoverResult check_subdomain_takeover(const std::string& subdomain);

// Performs a brute-force subdomain enumeration using a built-in wordlist.
std::vector<std::string> run_dns_subdomain_enum(const std::string& target);

// Performs passive subdomain enumeration via crt.sh (Certificate Transparency logs).
std::vector<std::string> run_passive_subdomain_enum(const std::string& target);

// Performs a reverse DNS lookup (PTR record) for the given IP address.
std::string run_reverse_dns(const std::string& ip);

// Performs a WHOIS query, following referrals to authoritative servers
// when possible (e.g. iana.org -> registry-specific server).
WhoisResult run_whois_lookup(const std::string& target);

#endif
