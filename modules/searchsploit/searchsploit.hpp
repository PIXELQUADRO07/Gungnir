#pragma once

#include <string>
#include <vector>

// ─── data structures ──────────────────────────────────────────────────────────

struct Exploit {
    std::string title;      // human-readable exploit name
    std::string path;       // path inside exploitdb (e.g. exploits/linux/remote/...)
    std::string type;       // "remote", "local", "dos", "webapps", etc.
    std::string platform;   // "linux", "windows", "multiple", etc.
};

struct SearchsploitResult {
    bool                  success = false;
    std::string           query;
    std::vector<Exploit>  exploits;
    std::string           error;
};

// ─── public API ───────────────────────────────────────────────────────────────

// Checks whether searchsploit is available on PATH.
std::string searchsploit_find();

// Queries searchsploit for the given term and returns structured results.
SearchsploitResult searchsploit_query(
    const std::string& query,
    bool               exact = false    // pass --exact to searchsploit
);
