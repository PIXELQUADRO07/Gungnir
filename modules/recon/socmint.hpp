#ifndef SOCMINT_HPP
#define SOCMINT_HPP

#include <string>
#include <vector>

struct SocSite {
    std::string name;
    std::string url_template; // e.g. "https://twitter.com/{}"
};

struct SocmintResult {
    std::string username;
    struct FoundSite {
        std::string name;
        std::string url;
    };
    std::vector<FoundSite> matches;
};

// Performs parallel search for a username across multiple social platforms.
SocmintResult run_socmint_search(const std::string& username);

#endif
