#include "nmap.hpp"
#include "logger.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <map>

// ─── subprocess helper ────────────────────────────────────────────────────────

namespace {

// Runs a shell command and returns its combined stdout.
// Returns empty string on failure.
std::string run_command(const std::string& cmd) {
    std::string output;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::array<char, 4096> buf;
    while (fgets(buf.data(), buf.size(), pipe))
        output += buf.data();
    pclose(pipe);
    return output;
}

// Trims leading and trailing whitespace in-place.
std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// ─── grepable output parser ───────────────────────────────────────────────────
//
// nmap -oG - produces lines like:
//   Host: 93.184.216.34 (example.com)  Status: Up
//   Host: 93.184.216.34 (example.com)  Ports: 80/open/tcp//http//Apache/, 443/open/tcp//https//
//   OS: Linux 4.x
//
// We parse these into NmapHost entries.

NmapResult parse_grepable(const std::string& raw) {
    NmapResult result;
    result.raw = raw;

    std::istringstream ss(raw);
    std::string line;

    // map ip → host (accumulate ports across lines)
    std::map<std::string, NmapHost> hosts_map;
    std::vector<std::string>        host_order;   // preserve insertion order

    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;

        // ── Host line ─────────────────────────────────────────────────────────
        if (line.rfind("Host:", 0) == 0) {
            // "Host: <ip> (<hostname>)  Status: ..."
            std::istringstream ls(line);
            std::string token;
            ls >> token;        // "Host:"
            std::string ip;
            ls >> ip;           // "93.184.216.34"

            std::string hostname;
            std::string rest;
            std::getline(ls, rest);
            auto lp = rest.find('(');
            auto rp = rest.find(')');
            if (lp != std::string::npos && rp != std::string::npos && rp > lp)
                hostname = rest.substr(lp + 1, rp - lp - 1);

            if (hosts_map.find(ip) == hosts_map.end()) {
                NmapHost h;
                h.ip       = ip;
                h.hostname = hostname;
                hosts_map[ip] = h;
                host_order.push_back(ip);
            }
            continue;
        }

        // ── Ports line ────────────────────────────────────────────────────────
        // "Host: <ip> (<host>)  Ports: 80/open/tcp//http//Apache HTTPd/, 443/open/tcp//https//"
        if (line.find("\tPorts:") != std::string::npos ||
            line.find(" Ports:") != std::string::npos) {

            // Extract IP from start of line (same format as Host line)
            std::istringstream ls(line);
            std::string tok;
            ls >> tok;           // "Host:"
            std::string ip;
            ls >> ip;

            // Find "Ports:" section
            auto ports_pos = line.find("Ports:");
            if (ports_pos == std::string::npos) continue;
            std::string ports_str = line.substr(ports_pos + 6);

            // Split by ", "
            std::istringstream ps(ports_str);
            std::string entry;
            while (std::getline(ps, entry, ',')) {
                entry = trim(entry);
                if (entry.empty()) continue;

                // Format: port/state/proto//service//version/
                // Fields separated by '/'
                std::vector<std::string> fields;
                std::istringstream fs(entry);
                std::string field;
                while (std::getline(fs, field, '/'))
                    fields.push_back(field);

                // fields[0]=port [1]=state [2]=proto [3]=? [4]=service [5]=? [6]=version
                if (fields.size() < 3) continue;

                NmapPort np;
                try { np.port = std::stoi(fields[0]); } catch (...) { continue; }
                np.state    = fields.size() > 1 ? trim(fields[1]) : "";
                np.protocol = fields.size() > 2 ? trim(fields[2]) : "";
                np.service  = fields.size() > 4 ? trim(fields[4]) : "";
                np.version  = fields.size() > 6 ? trim(fields[6]) : "";

                if (hosts_map.find(ip) != hosts_map.end())
                    hosts_map[ip].ports.push_back(np);
            }
            continue;
        }

        // ── OS line ───────────────────────────────────────────────────────────
        if (line.rfind("OS:", 0) == 0) {
            // "OS: Linux 4.x"  — attribute to last host seen
            if (!host_order.empty()) {
                std::string os = trim(line.substr(3));
                hosts_map[host_order.back()].os_guess = os;
            }
            continue;
        }
    }

    for (const auto& ip : host_order)
        result.hosts.push_back(hosts_map[ip]);

    result.success = !result.hosts.empty();
    return result;
}

} // namespace

// ─── public API ───────────────────────────────────────────────────────────────

std::string nmap_find() {
    const std::string out = run_command("which nmap 2>/dev/null");
    std::string path = out;
    // trim newline
    while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
        path.pop_back();
    return path;
}

NmapResult nmap_scan(
    const std::string&              target,
    const std::vector<std::string>& extra_args,
    const std::vector<int>&         ports
) {
    const std::string nmap_path = nmap_find();
    if (nmap_path.empty()) {
        NmapResult r;
        r.error = "nmap not found on PATH. Install it with: sudo apt install nmap";
        return r;
    }

    // Build command:
    //   nmap -sV           — service/version detection
    //        -oG -          — grepable output to stdout (we parse this)
    //        -p <ports>     — if ports specified
    //        <extra_args>   — user-supplied flags (e.g. -sU, -A, --script)
    //        <target>
    std::ostringstream cmd;
    cmd << nmap_path << " -sV -oG -";

    if (!ports.empty()) {
        cmd << " -p ";
        for (size_t i = 0; i < ports.size(); ++i) {
            if (i) cmd << ",";
            cmd << ports[i];
        }
    }

    for (const auto& arg : extra_args)
        cmd << " " << arg;

    cmd << " " << target << " 2>&1";

    Logger::info("Running: " + cmd.str());

    const std::string raw = run_command(cmd.str());
    if (raw.empty()) {
        NmapResult r;
        r.error = "nmap produced no output.";
        return r;
    }

    NmapResult result = parse_grepable(raw);
    result.raw = raw;

    if (!result.success && result.error.empty())
        result.error = "No hosts found or all ports filtered.";

    return result;
}
