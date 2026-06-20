#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace mscanner {

enum class RiskLevel {
    SAFE,
    SUSPICIOUS,
    HIGH_RISK
};

inline std::string riskLevelToString(RiskLevel level) {
    switch (level) {
        case RiskLevel::SAFE:      return "SAFE";
        case RiskLevel::SUSPICIOUS:return "SUSPICIOUS";
        case RiskLevel::HIGH_RISK: return "HIGH RISK";
    }
    return "UNKNOWN";
}

struct RiskFlag {
    std::string reason;
    int         points;
};

struct FileInfo {
    std::string            filename;
    std::string            extension;        // lowercase, e.g. ".exe"
    std::string            filepath;         // absolute path
    uintmax_t              size = 0;         // bytes
    std::string            lastModified;     // human-readable

    double                 entropy  = 0.0;
    int                    riskScore = 0;
    RiskLevel              riskLevel = RiskLevel::SAFE;
    std::vector<RiskFlag>  flags;            // what triggered points

    bool isHidden        = false;
    bool hasDoubleExt    = false;
    bool hasKeyword      = false;
    bool isSuspiciousExt = false;
    bool isLargeExec     = false;
};

} // namespace mscanner
