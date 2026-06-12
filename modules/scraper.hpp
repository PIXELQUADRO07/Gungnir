#ifndef SCRAPER_HPP
#define SCRAPER_HPP

#include <string>
#include <vector>

struct ScrapeResult {
    std::string title;
    std::string server_header;
    std::string cms;
    std::vector<std::string> emails;
    std::vector<std::string> social_links;
    std::vector<std::string> phone_numbers;
    std::vector<std::string> robots_entries;
    std::vector<std::string> historical_urls;
    bool success = false;
};

struct FuzzResult {
    std::string url;
    int status_code;
    size_t length;
};

struct S3Result {
    std::string bucket_name;
    bool exists = false;
    bool public_read = false;
};

ScrapeResult start_web_scrape(const std::string& target);
std::vector<FuzzResult> start_web_fuzz(const std::string& target);
std::vector<S3Result> start_s3_enum(const std::string& target);

#endif
