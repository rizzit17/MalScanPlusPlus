#include "Scanner.h"
#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <stdexcept>

namespace mscanner {

Scanner::Scanner(bool verbose) : verbose_(verbose) {}

// ─── Main scan entry point ────────────────────────────────────────────────────

std::vector<FileInfo> Scanner::scan(const std::filesystem::path& root) {
    namespace fs = std::filesystem;

    if (!fs::exists(root)) {
        throw std::runtime_error("Path does not exist: " + root.string());
    }

    std::cout << Color::CYAN << Color::BOLD
              << "\n+------------------------------------------------------+\n"
              << "|         MalwareScanner - Static Analysis Tool        |\n"
              << "+------------------------------------------------------+\n"
              << Color::RESET;
    std::cout << Color::DIM << "  Target: " << fs::absolute(root).string()
              << Color::RESET << "\n\n";

    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<FileInfo> results;

    // Use recursive_directory_iterator with error handling
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ++stats_.skipped; ec.clear(); continue; }

        const auto& entry = *it;
        if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }

        try {
            FileInfo fi = collectMetadata(entry.path());
            engine_.evaluate(fi);
            printResult(fi);
            results.push_back(fi);
            ++stats_.totalFiles;
            switch (fi.riskLevel) {
                case RiskLevel::SAFE:       ++stats_.safeFiles;  break;
                case RiskLevel::SUSPICIOUS: ++stats_.suspicious;  break;
                case RiskLevel::HIGH_RISK:  ++stats_.highRisk;    break;
            }
        } catch (...) {
            ++stats_.skipped;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    stats_.scanTimeMs =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Summary banner
    std::cout << "\n" << Color::BOLD
              << "-------------------- SCAN SUMMARY -----------------------\n"
              << Color::RESET;
    std::cout << "  Files scanned : " << stats_.totalFiles  << "\n";
    std::cout << Color::GREEN  << "  Safe          : " << stats_.safeFiles  << Color::RESET << "\n";
    std::cout << Color::YELLOW << "  Suspicious    : " << stats_.suspicious  << Color::RESET << "\n";
    std::cout << Color::RED    << "  High Risk     : " << stats_.highRisk    << Color::RESET << "\n";
    std::cout << Color::DIM    << "  Skipped       : " << stats_.skipped
              << "  |  Time: " << std::fixed << std::setprecision(1)
              << stats_.scanTimeMs << " ms\n" << Color::RESET;
    std::cout << Color::BOLD
              << "----------------------------------------------------------\n\n"
              << Color::RESET;

    return results;
}

// ─── Metadata collection ──────────────────────────────────────────────────────

FileInfo Scanner::collectMetadata(const std::filesystem::path& p) const {
    namespace fs = std::filesystem;

    FileInfo fi;
    fi.filepath  = fs::absolute(p).string();
    fi.filename  = p.filename().string();
    fi.extension = Utils::toLower(p.extension().string());

    std::error_code ec;
    fi.size = fs::file_size(p, ec);
    if (ec) fi.size = 0;

    auto lwt = fs::last_write_time(p, ec);
    if (!ec) fi.lastModified = Utils::fileTimeToString(lwt);

    return fi;
}

// ─── Console output ───────────────────────────────────────────────────────────

void Scanner::printResult(const FileInfo& fi) const {
    const std::string col   = colorForRisk(fi.riskLevel);
    const std::string label = riskLevelToString(fi.riskLevel);

    // Always print high-risk; conditionally print others in verbose mode
    if (fi.riskLevel == RiskLevel::SAFE && !verbose_) return;

    std::cout << col << "  [" << std::setw(9) << label << "] " << Color::RESET
              << fi.filename
              << Color::DIM << "  (" << Utils::humanSize(fi.size)
              << "  entropy=" << std::fixed << std::setprecision(2) << fi.entropy
              << "  score=" << fi.riskScore << ")"
              << Color::RESET << "\n";

    if (verbose_ || fi.riskLevel == RiskLevel::HIGH_RISK) {
        for (const auto& flag : fi.flags) {
            std::cout << Color::DIM << "     -> " << flag.reason
                      << " [+" << flag.points << "]" << Color::RESET << "\n";
        }
    }
}

} // namespace mscanner
