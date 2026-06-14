#include "nmap.hpp"
#include "logger.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <regex>

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

// Decodes the handful of XML entities nmap emits in attribute values.
std::string xml_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == '&') {
            if (s.compare(i, 5, "&amp;")  == 0) { out += '&';  i += 5; continue; }
            if (s.compare(i, 4, "&lt;")   == 0) { out += '<';  i += 4; continue; }
            if (s.compare(i, 4, "&gt;")   == 0) { out += '>';  i += 4; continue; }
            if (s.compare(i, 6, "&quot;") == 0) { out += '"';  i += 6; continue; }
            if (s.compare(i, 6, "&apos;") == 0) { out += '\''; i += 6; continue; }
        }
        out += s[i++];
    }
    return out;
}

// Extracts the value of attribute `name="..."` from a fragment of XML
// attributes (e.g. the inside of a <service ...> tag). Returns "" if absent.
std::string xml_attr(const std::string& attrs, const std::string& name) {
    const std::regex re(name + "=\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(attrs, m, re)) return xml_unescape(m[1].str());
    return "";
}

// ─── XML output parser ────────────────────────────────────────────────────────
//
// nmap -oX - emits a <host> element per host, containing <address>,
// <hostnames>, an <os> block with <osmatch> guesses, and a <ports> block
// with one <port> element per scanned port. Each <port> has a <state> and
// a <service> element (which carries name/product/version/extrainfo and,
// when nmap could determine one, a nested <cpe> element).
//
// This is a lightweight regex-based extraction rather than a full XML
// parser. It is tolerant of attribute order and self-closing tags, but
// assumes nmap's own (well-formed, predictable) output — it is not a
// general-purpose XML parser.

NmapResult parse_xml(const std::string& raw) {
    NmapResult result;
    result.raw = raw;

    const std::regex host_re("<host>([\\s\\S]*?)</host>");
    const std::regex addr_re("<address addr=\"([^\"]+)\" addrtype=\"ip");
    const std::regex hostname_re("<hostname name=\"([^\"]+)\"");
    const std::regex osmatch_re("<osmatch name=\"([^\"]+)\"");
    const std::regex port_re("<port protocol=\"([^\"]+)\" portid=\"(\\d+)\">([\\s\\S]*?)</port>");
    const std::regex state_re("<state state=\"([^\"]+)\"");
    const std::regex service_re("<service([\\s\\S]*?)(?:/>|>)");
    const std::regex cpe_re("<cpe>([^<]+)</cpe>");

    for (auto it = std::sregex_iterator(raw.begin(), raw.end(), host_re);
         it != std::sregex_iterator(); ++it) {
        const std::string hblock = (*it)[1].str();

        NmapHost host;
        std::smatch m;

        if (std::regex_search(hblock, m, addr_re))
            host.ip = m[1].str();
        if (host.ip.empty()) continue;  // host down / no address

        if (std::regex_search(hblock, m, hostname_re))
            host.hostname = xml_unescape(m[1].str());

        if (std::regex_search(hblock, m, osmatch_re))
            host.os_guess = xml_unescape(m[1].str());

        for (auto pit = std::sregex_iterator(hblock.begin(), hblock.end(), port_re);
             pit != std::sregex_iterator(); ++pit) {
            NmapPort port;
            port.protocol = (*pit)[1].str();
            try { port.port = std::stoi((*pit)[2].str()); } catch (...) { continue; }

            const std::string pblock = (*pit)[3].str();

            if (std::regex_search(pblock, m, state_re))
                port.state = m[1].str();

            if (std::regex_search(pblock, m, service_re)) {
                const std::string svc_attrs = m[1].str();
                port.service   = xml_attr(svc_attrs, "name");
                port.product   = xml_attr(svc_attrs, "product");
                port.version   = xml_attr(svc_attrs, "version");
                port.extrainfo = xml_attr(svc_attrs, "extrainfo");
            }

            if (std::regex_search(pblock, m, cpe_re))
                port.cpe = xml_unescape(m[1].str());

            host.ports.push_back(port);
        }

        result.hosts.push_back(host);
    }

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
    //        -oX -          — XML output to stdout (we parse this; XML
    //                         carries product/version/extrainfo/cpe, which
    //                         the old grepable (-oG) format did not)
    //        -p <ports>     — if ports specified
    //        <extra_args>   — user-supplied flags (e.g. -sU, -A, --script)
    //        <target>
    std::ostringstream cmd;
    cmd << nmap_path << " -sV -oX -";

    if (!ports.empty()) {
        cmd << " -p ";
        for (size_t i = 0; i < ports.size(); ++i) {
            if (i) cmd << ",";
            cmd << ports[i];
        }
    }

    for (const auto& arg : extra_args)
        cmd << " " << arg;

    // Send stderr to /dev/null rather than merging it into stdout: with
    // -oX the parser expects well-formed XML on stdout, and interleaved
    // progress/diagnostic lines from stderr could land inside a <host>
    // block and break the regex-based extraction below.
    cmd << " " << target << " 2>/dev/null";

    Logger::info("Running: " + cmd.str());

    const std::string raw = run_command(cmd.str());
    if (raw.empty()) {
        NmapResult r;
        r.error = "nmap produced no output.";
        return r;
    }

    NmapResult result = parse_xml(raw);

    if (!result.success && result.error.empty())
        result.error = "No hosts found or all ports filtered.";

    return result;
}
