#include "recon.hpp"
#include "logger.hpp"

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

    return result;
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
    }

    return result;
}
