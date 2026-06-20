#pragma once
#include <string>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <chrono>
#include <ctime>
#include <filesystem>
#include "FileInfo.h"

namespace mscanner {

// ─── ANSI color codes ────────────────────────────────────────────────────────
namespace Color {
    inline constexpr const char* RESET   = "\033[0m";
    inline constexpr const char* RED     = "\033[1;31m";
    inline constexpr const char* YELLOW  = "\033[1;33m";
    inline constexpr const char* GREEN   = "\033[1;32m";
    inline constexpr const char* CYAN    = "\033[1;36m";
    inline constexpr const char* MAGENTA = "\033[1;35m";
    inline constexpr const char* BOLD    = "\033[1m";
    inline constexpr const char* DIM     = "\033[2m";
}

inline std::string colorForRisk(RiskLevel level) {
    switch (level) {
        case RiskLevel::SAFE:       return Color::GREEN;
        case RiskLevel::SUSPICIOUS: return Color::YELLOW;
        case RiskLevel::HIGH_RISK:  return Color::RED;
    }
    return Color::RESET;
}

namespace Utils {

// ─── String utilities ─────────────────────────────────────────────────────────
inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

inline bool containsSubstringCI(const std::string& haystack,
                                 const std::string& needle) {
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

// ─── File size pretty print ───────────────────────────────────────────────────
inline std::string humanSize(uintmax_t bytes) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double val = static_cast<double>(bytes);
    int u = 0;
    while (val >= 1024.0 && u < 4) { val /= 1024.0; ++u; }
    std::ostringstream oss;
    oss.precision(2);
    oss << std::fixed << val << " " << units[u];
    return oss.str();
}

// ─── Timestamp ────────────────────────────────────────────────────────────────
inline std::string fileTimeToString(const std::filesystem::file_time_type& ft) {
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ft - std::filesystem::file_time_type::clock::now()
          + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
    return std::string(buf);
}

} // namespace Utils
} // namespace mscanner
