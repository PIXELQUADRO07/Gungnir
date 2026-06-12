#ifndef REPORT_GEN_HPP
#define REPORT_GEN_HPP

#include <string>
#include <vector>
#include "database.hpp"

namespace ReportGen {

enum class Format {
    HTML,
    JSON
};

struct FullReportData {
    std::string target;
    std::vector<HistoryEntry> scans;
    std::vector<ServiceInfo> services;
    // Potremmo aggiungere DNS records qui in futuro
};

bool generate(const std::string& target, const std::string& output_path, Format fmt, Database& db);

} // namespace ReportGen

#endif
