#ifndef SCRAPER_HPP
#define SCRAPER_HPP

#include <string>
#include <vector>

struct ScrapeResult {
    std::string title;
    std::string server_header;
    std::vector<std::string> emails;
    bool success = false;
};

ScrapeResult start_web_scrape(const std::string& target);

#endif
