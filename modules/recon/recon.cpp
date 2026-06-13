#include "recon.hpp"
#include "logger.hpp"
#include "http_client.hpp"
#include "json.hpp"
#include <set>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <resolv.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>

namespace {
    constexpr int WHOIS_PORT = 43;
    constexpr const char* IANA_WHOIS = "whois.iana.org";

    // Parses a single DNS resource record from a response buffer.
    bool parse_record(ns_msg& handle, int index, DnsRecord& out_record) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, index, &rr) != 0) {
            return false;
        }

        const u_char* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);

        switch (ns_rr_type(rr)) {
            case ns_t_a: {
                if (rdlen != 4) return false;
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rdata, buf, sizeof(buf));
                out_record.type = "A";
                out_record.value = buf;
                return true;
            }
            case ns_t_aaaa: {
                if (rdlen != 16) return false;
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rdata, buf, sizeof(buf));
                out_record.type = "AAAA";
                out_record.value = buf;
                return true;
            }
            case ns_t_ns: {
                char name[NS_MAXDNAME];
                if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata, name, sizeof(name)) < 0) {
                    return false;
                }
                out_record.type = "NS";
                out_record.value = name;
                return true;
            }
            case ns_t_cname: {
                char name[NS_MAXDNAME];
                if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata, name, sizeof(name)) < 0) {
                    return false;
                }
                out_record.type = "CNAME";
                out_record.value = name;
                return true;
            }
            case ns_t_mx: {
                if (rdlen < 3) return false;
                const int priority = ns_get16(rdata);
                char name[NS_MAXDNAME];
                if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata + 2, name, sizeof(name)) < 0) {
                    return false;
                }
                out_record.type = "MX";
                out_record.value = name;
                out_record.priority = priority;
                return true;
            }
            case ns_t_txt: {
                if (rdlen < 1) return false;
                const int len = rdata[0];
                if (len > rdlen - 1) return false;
                out_record.type = "TXT";
                out_record.value = std::string(reinterpret_cast<const char*>(rdata + 1), len);
                return true;
            }
            case ns_t_soa: {
                char mname[NS_MAXDNAME];
                if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata, mname, sizeof(mname)) < 0) {
                    return false;
                }
                out_record.type = "SOA";
                out_record.value = mname;
                return true;
            }
            default:
                return false;
        }
    }

    // Queries a specific DNS record type and appends results to the output vector.
    void query_record_type(const std::string& target, int rr_type, std::vector<DnsRecord>& out) {
        unsigned char response[NS_PACKETSZ * 4];
        const int response_len = res_query(target.c_str(), ns_c_in, rr_type, response, sizeof(response));
        if (response_len < 0) {
            return;
        }

        ns_msg handle;
        if (ns_initparse(response, response_len, &handle) != 0) {
            return;
        }

        const int answer_count = ns_msg_count(handle, ns_s_an);
        for (int i = 0; i < answer_count; ++i) {
            DnsRecord record;
            if (parse_record(handle, i, record)) {
                out.push_back(record);
            }
        }
    }

    // Opens a TCP connection to host:port with a connection timeout (milliseconds).
    int connect_to_host(const std::string& host, int port, int timeout_ms = 4000) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* result = nullptr;
        const std::string port_str = std::to_string(port);
        if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
            return -1;
        }

        int sock = -1;
        for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
            sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sock < 0) {
                continue;
            }

            const int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            int rc = connect(sock, p->ai_addr, p->ai_addrlen);
            if (rc == 0) {
                fcntl(sock, F_SETFL, flags);
                break;
            }

            if (errno != EINPROGRESS) {
                close(sock);
                sock = -1;
                continue;
            }

            pollfd pfd{};
            pfd.fd = sock;
            pfd.events = POLLOUT;
            rc = poll(&pfd, 1, timeout_ms);

            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            if (rc <= 0 || getsockopt(sock, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 || socket_error != 0) {
                close(sock);
                sock = -1;
                continue;
            }

            fcntl(sock, F_SETFL, flags);
            break;
        }

        freeaddrinfo(result);
        return sock;
    }

    // Sends a WHOIS query and reads the full text response.
    std::string query_whois_server(const std::string& server, const std::string& query) {
        const int sock = connect_to_host(server, WHOIS_PORT);
        if (sock < 0) {
            return {};
        }

        timeval recv_timeout{};
        recv_timeout.tv_sec = 5;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

        const std::string request = query + "\r\n";
        if (send(sock, request.c_str(), request.size(), 0) < 0) {
            close(sock);
            return {};
        }

        std::string response;
        char buffer[4096];
        ssize_t bytes_read;
        while ((bytes_read = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
            response.append(buffer, bytes_read);
        }

        close(sock);
        return response;
    }

    // Extracts the "refer:" or "whois:" server from an IANA/registry response, if present.
    std::string extract_referral_server(const std::string& whois_data) {
        std::istringstream stream(whois_data);
        std::string line;

        while (std::getline(stream, line)) {
            // Trim trailing carriage return.
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            const std::vector<std::string> prefixes = {"refer:", "whois:", "ReferralServer:"};
            for (const auto& prefix : prefixes) {
                if (line.compare(0, prefix.size(), prefix) == 0) {
                    std::string value = line.substr(prefix.size());

                    // Strip "rwhois://" or "whois://" schemes if present.
                    const auto scheme_pos = value.find("://");
                    if (scheme_pos != std::string::npos) {
                        value = value.substr(scheme_pos + 3);
                    }

                    // Trim whitespace.
                    const auto begin = value.find_first_not_of(" \t");
                    const auto end = value.find_last_not_of(" \t");
                    if (begin == std::string::npos) {
                        continue;
                    }
                    return value.substr(begin, end - begin + 1);
                }
            }
        }

        return {};
    }
}

DnsResult run_dns_lookup(const std::string& target) {
    DnsResult result;
    result.target = target;

    // Check if target is an IP (v4 or v6)
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    bool is_ip = (inet_pton(AF_INET, target.c_str(), &(sa.sin_addr)) == 1 ||
                  inet_pton(AF_INET6, target.c_str(), &(sa6.sin6_addr)) == 1);

    if (is_ip) {
        Logger::info("Target is an IP address. Performing Reverse DNS lookup...");
        std::string hostname = run_reverse_dns(target);
        if (!hostname.empty()) {
            DnsRecord rec;
            rec.type = "PTR";
            rec.value = hostname;
            result.records.push_back(rec);
            result.success = true;
        } else {
            Logger::warn("No Reverse DNS record found for " + target);
        }
        return result;
    }

    if (res_init() != 0) {
        Logger::error("Unable to initialize DNS resolver");
        return result;
    }

    query_record_type(target, ns_t_a, result.records);
    query_record_type(target, ns_t_aaaa, result.records);
    query_record_type(target, ns_t_ns, result.records);
    query_record_type(target, ns_t_mx, result.records);
    query_record_type(target, ns_t_txt, result.records);
    query_record_type(target, ns_t_soa, result.records);

    // If no A record was found directly, the target may itself be a CNAME.
    if (std::none_of(result.records.begin(), result.records.end(),
                      [](const DnsRecord& r) { return r.type == "A" || r.type == "AAAA"; })) {
        query_record_type(target, ns_t_cname, result.records);
    }

    result.success = !result.records.empty();
    if (!result.success) {
        Logger::warn("No DNS records found for " + target);
    }

    // Combine brute-force and passive subdomain enumeration
    auto brute_subs = run_dns_subdomain_enum(target);
    auto passive_subs = run_passive_subdomain_enum(target);

    std::set<std::string> all_subs(brute_subs.begin(), brute_subs.end());
    for (const auto& s : passive_subs) all_subs.insert(s);

    result.subdomains.assign(all_subs.begin(), all_subs.end());

    return result;
}

std::vector<std::string> run_dns_subdomain_enum(const std::string& target) {
    const std::vector<std::string> wordlist = {
        "www", "mail", "dev", "test", "api", "admin", "blog", "staging",
        "vpn", "smtp", "pop", "imap", "ns1", "ns2", "ftp", "portal",
        "dev", "prod", "stage", "git", "ssh", "web", "app", "m", "db",
        "cloud", "static", "assets", "cdn", "shop", "api", "v1", "v2",
        "support", "billing", "beta", "demo", "internal", "corp", "alpha",
        "secure", "payment", "login", "register", "status", "api-docs",
        "jenkins", "gitlab", "docker", "monitor", "grafana", "prometheus"
    };

    std::vector<std::string> found;
    std::mutex result_mutex;
    std::atomic<size_t> next_index{0};

    const size_t thread_count = std::min(static_cast<size_t>(50), wordlist.size());
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (size_t i = 0; i < thread_count; ++i) {
        workers.emplace_back([&] {
            while (true) {
                const size_t index = next_index.fetch_add(1, std::memory_order_relaxed);
                if (index >= wordlist.size()) break;

                const std::string subdomain = wordlist[index] + "." + target;
                addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                addrinfo* res = nullptr;

                if (getaddrinfo(subdomain.c_str(), nullptr, &hints, &res) == 0) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    found.push_back(subdomain);
                    freeaddrinfo(res);
                }
            }
        });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    return found;
}

std::vector<std::string> run_passive_subdomain_enum(const std::string& target) {
    std::vector<std::string> subdomains;
    std::set<std::string> unique_subs;

    // --- crt.sh ---
    const std::string crt_url = "https://crt.sh/?q=%25." + target + "&output=json";
    Logger::info("Enumerazione passiva subdomains (crt.sh) per: " + target);
    HttpResponse crt_resp = HttpClient::get(crt_url, {}, 20);

    if (crt_resp.status_code == 200) {
        try {
            auto j = nlohmann::json::parse(crt_resp.body);
            for (const auto& item : j) {
                if (item.contains("common_name")) {
                    std::string cn = item["common_name"].get<std::string>();
                    std::stringstream ss(cn);
                    std::string segment;
                    while (std::getline(ss, segment, '\n')) {
                        if (segment.substr(0, 2) == "*.") segment = segment.substr(2);
                        if (segment.find(target) != std::string::npos && segment != target) 
                            unique_subs.insert(segment);
                    }
                }
                if (item.contains("name_value")) {
                    std::string nv = item["name_value"].get<std::string>();
                    std::stringstream ss(nv);
                    std::string segment;
                    while (std::getline(ss, segment, '\n')) {
                        if (segment.substr(0, 2) == "*.") segment = segment.substr(2);
                        if (segment.find(target) != std::string::npos && segment != target) 
                            unique_subs.insert(segment);
                    }
                }
            }
        } catch (...) {}
    }

    // --- AlienVault OTX ---
    const std::string av_url = "https://otx.alienvault.com/api/v1/indicators/domain/" + target + "/passive_dns";
    Logger::info("Enumerazione passiva subdomains (AlienVault) per: " + target);
    HttpResponse av_resp = HttpClient::get(av_url, {}, 15);
    if (av_resp.status_code == 200) {
        try {
            auto j = nlohmann::json::parse(av_resp.body);
            if (j.contains("passive_dns")) {
                for (const auto& item : j["passive_dns"]) {
                    if (item.contains("hostname")) {
                        std::string hostname = item["hostname"].get<std::string>();
                        if (hostname.find(target) != std::string::npos && hostname != target) {
                            unique_subs.insert(hostname);
                        }
                    }
                }
            }
        } catch (...) {}
    }

    for (const auto& sub : unique_subs) {
        subdomains.push_back(sub);
    }
    
    std::sort(subdomains.begin(), subdomains.end());
    return subdomains;
}

std::string run_reverse_dns(const std::string& ip) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    char host[NI_MAXHOST];

    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1) {
        sa.sin_family = AF_INET;
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return std::string(host);
        }
    } else if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
        sa6.sin6_family = AF_INET6;
        if (getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return std::string(host);
        }
    }

    return "";
}

TakeoverResult check_subdomain_takeover(const std::string& subdomain) {
    TakeoverResult res;
    res.subdomain = subdomain;

    // Get CNAME
    unsigned char buf[4096];
    int len = res_query(subdomain.c_str(), ns_c_in, ns_t_cname, buf, sizeof(buf));
    if (len < 0) return res;

    ns_msg handle;
    if (ns_initparse(buf, len, &handle) < 0) return res;

    for (int i = 0; i < ns_msg_count(handle, ns_s_an); ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            char cname[MAXDNAME];
            if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), cname, sizeof(cname)) >= 0) {
                res.cname = cname;
                break;
            }
        }
    }

    if (res.cname.empty()) return res;

    // Common signatures
    struct Sig { std::string domain; std::string provider; std::string error; };
    static const std::vector<Sig> signatures = {
        {"github.io", "GitHub Pages", "404 Not Found"},
        {"herokudns.com", "Heroku", "No such app"},
        {"herokuapp.com", "Heroku", "No such app"},
        {"s3.amazonaws.com", "AWS S3", "NoSuchBucket"},
        {"cloudfront.net", "AWS CloudFront", "Bad Gateway"},
        {"azurewebsites.net", "Azure", "404 Not Found"},
        {"bitbucket.io", "Bitbucket", "404 Not Found"},
        {"zendesk.com", "Zendesk", "No help center found"},
        {"shopify.com", "Shopify", "No such shop"}
    };

    for (const auto& sig : signatures) {
        if (res.cname.find(sig.domain) != std::string::npos) {
            res.provider = sig.provider;
            // Verify if the provider actually reports a missing service
            HttpResponse h_resp = HttpClient::get("http://" + subdomain);
            if (h_resp.status_code == 404 || h_resp.body.find(sig.error) != std::string::npos) {
                res.vulnerable = true;
            }
            break;
        }
    }

    return res;
}

WhoisResult run_whois_lookup(const std::string& target) {
    WhoisResult result;
    result.target = target;

    // Step 1: ask IANA which registry is authoritative for this TLD/target.
    std::string referral_query = target;
    const auto last_dot = target.find_last_of('.');
    const std::string tld = (last_dot != std::string::npos) ? target.substr(last_dot + 1) : target;

    std::string current_server = IANA_WHOIS;
    std::string response = query_whois_server(current_server, tld);

    if (response.empty()) {
        Logger::error("Unable to contact the IANA WHOIS server");
        return result;
    }

    // Step 2: follow referral to the registry-specific WHOIS server.
    std::string referral = extract_referral_server(response);
    if (!referral.empty()) {
        current_server = referral;
        const std::string registry_response = query_whois_server(current_server, target);
        if (!registry_response.empty()) {
            response = registry_response;

            // Step 3: some registries (e.g. Verisign for .com/.net) return a
            // further referral to the registrar's own WHOIS server.
            const std::string registrar_referral = extract_referral_server(response);
            if (!registrar_referral.empty() && registrar_referral != current_server) {
                const std::string registrar_response = query_whois_server(registrar_referral, target);
                if (!registrar_response.empty()) {
                    current_server = registrar_referral;
                    response = registrar_response;
                }
            }
        }
    }

    result.whois_server = current_server;
    result.raw_data = response;
    result.success = !response.empty();

    if (!result.success) {
        Logger::warn("No WHOIS data found for " + target);
    } else {
        // Parse structured fields
        std::istringstream stream(response);
        std::string line;
        while (std::getline(stream, line)) {
            // Trim carriage return
            if (!line.empty() && line.back() == '\r') line.pop_back();

            std::string lower_line = line;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

            // Simple prefix matching
            auto extract_value = [](const std::string& l, const std::string& prefix) -> std::string {
                auto pos = l.find(":");
                if (pos != std::string::npos && pos + 1 < l.size()) {
                    std::string val = l.substr(pos + 1);
                    auto begin = val.find_first_not_of(" \t");
                    if (begin == std::string::npos) return "";
                    auto end = val.find_last_not_of(" \t");
                    return val.substr(begin, end - begin + 1);
                }
                return "";
            };

            if (lower_line.find("registrar:") == 0) {
                if (result.registrar.empty()) result.registrar = extract_value(line, "Registrar:");
            } else if (lower_line.find("creation date:") == 0 || lower_line.find("created:") == 0) {
                if (result.creation_date.empty()) result.creation_date = extract_value(line, "Creation Date:");
            } else if (lower_line.find("registry expiry date:") == 0 || lower_line.find("expiry date:") == 0) {
                if (result.expiry_date.empty()) result.expiry_date = extract_value(line, "Registry Expiry Date:");
            } else if (lower_line.find("name server:") == 0) {
                std::string ns = extract_value(line, "Name Server:");
                if (!ns.empty()) {
                    std::transform(ns.begin(), ns.end(), ns.begin(), ::tolower);
                    if (std::find(result.name_servers.begin(), result.name_servers.end(), ns) == result.name_servers.end()) {
                        result.name_servers.push_back(ns);
                    }
                }
            }
        }
    }

    return result;
}

std::vector<std::string> run_reverse_ip_lookup(const std::string& ip) {
    std::vector<std::string> domains;
    std::string url = "https://api.hackertarget.com/reverseiplookup/?q=" + ip;
    
    Logger::info("Reverse IP lookup (HackerTarget) per: " + ip);
    HttpResponse resp = HttpClient::get(url);
    
    if (resp.status_code == 200) {
        std::istringstream ss(resp.body);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.find("error") == std::string::npos && line.find("API count") == std::string::npos) {
                domains.push_back(line);
            }
        }
    } else {
        Logger::error("HackerTarget API fallito con codice: " + std::to_string(resp.status_code));
    }
    
    return domains;
}
