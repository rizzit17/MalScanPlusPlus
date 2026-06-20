#pragma once
#include "FileInfo.h"
#include <vector>
#include <string>

namespace mscanner {

/*
 * ReportGenerator produces JSON and CSV reports.
 *
 * JSON: uses nlohmann/json (header-only, no runtime deps).
 * CSV:  plain std::ofstream – zero dependencies.
 *
 * Strategy pattern: each format is its own method; a future
 * HTML or SARIF report is one new method + zero changes elsewhere.
 */
class ReportGenerator {
public:
    // Generates JSON string directly
    static std::string getJSONString(const std::vector<FileInfo>& results);

    // Writes JSON report; returns output path
    static std::string writeJSON(const std::vector<FileInfo>& results,
                                 const std::string& outDir = "reports");

    // Writes CSV report; returns output path
    static std::string writeCSV (const std::vector<FileInfo>& results,
                                 const std::string& outDir = "reports");

private:
    static std::string timestamp();
    static void        ensureDir(const std::string& dir);
};

} // namespace mscanner
