#pragma once
#include "FileInfo.h"
#include "RiskEngine.h"
#include <filesystem>
#include <vector>
#include <string>
#include <atomic>

namespace mscanner {

struct ScanStats {
    size_t totalFiles    = 0;
    size_t safeFiles     = 0;
    size_t suspicious    = 0;
    size_t highRisk      = 0;
    size_t skipped       = 0;   // permission errors, etc.
    double scanTimeMs    = 0.0;
};

/*
 * Scanner orchestrates:
 *  1. Recursive filesystem traversal (std::filesystem::recursive_directory_iterator)
 *  2. Metadata collection into FileInfo
 *  3. Delegation to RiskEngine for scoring
 *  4. Live console output during scan
 */
class Scanner {
public:
    explicit Scanner(bool verbose = false);

    // Entry point – returns all scanned results
    std::vector<FileInfo> scan(const std::filesystem::path& root);

    const ScanStats& stats() const { return stats_; }

private:
    FileInfo   collectMetadata(const std::filesystem::path& p) const;
    void       printResult   (const FileInfo& fi)              const;

    RiskEngine engine_;
    ScanStats  stats_;
    bool       verbose_;
};

} // namespace mscanner
