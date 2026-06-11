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
    bool success = false;
};

struct WhoisResult {
    std::string target;
    std::string raw_data;
    std::string whois_server;
    bool success = false;
};

// Performs DNS lookups for A, AAAA, MX, NS, TXT and CNAME records.
DnsResult run_dns_lookup(const std::string& target);

// Performs a WHOIS query, following referrals to authoritative servers
// when possible (e.g. iana.org -> registry-specific server).
WhoisResult run_whois_lookup(const std::string& target);

#endif
