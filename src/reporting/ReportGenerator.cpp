#include "ReportGenerator.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include "Utils.h"
#include "EntropyAnalyzer.h"

namespace mscanner {

using json = nlohmann::json;

void ReportGenerator::ensureDir(const std::string& dir) {
    std::filesystem::create_directories(dir);
}

std::string ReportGenerator::timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y%m%d_%H%M%S");
    return oss.str();
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

std::string ReportGenerator::getJSONString(const std::vector<FileInfo>& results) {
    json report;
    report["generated_at"] = timestamp();
    report["total_files"]  = results.size();

    json arr = json::array();
    for (const auto& fi : results) {
        json entry;
        entry["file"]            = fi.filename;
        entry["path"]            = fi.filepath;
        entry["size_bytes"]      = fi.size;
        entry["size_human"]      = Utils::humanSize(fi.size);
        entry["extension"]       = fi.extension;
        entry["entropy"]         = std::round(fi.entropy * 100.0) / 100.0;
        entry["entropy_band"]    = EntropyAnalyzer::band(fi.entropy);
        entry["risk_score"]      = fi.riskScore;
        entry["classification"]  = riskLevelToString(fi.riskLevel);
        entry["last_modified"]   = fi.lastModified;
        entry["is_hidden"]       = fi.isHidden;
        entry["double_extension"]= fi.hasDoubleExt;

        json flags = json::array();
        for (const auto& f : fi.flags) {
            json flag;
            flag["reason"] = f.reason;
            flag["points"] = f.points;
            flags.push_back(flag);
        }
        entry["flags"] = flags;
        arr.push_back(entry);
    }
    report["results"] = arr;
    return report.dump(2);
}

std::string ReportGenerator::writeJSON(const std::vector<FileInfo>& results,
                                        const std::string& outDir) {
    ensureDir(outDir);
    std::string path = outDir + "/scan_" + timestamp() + ".json";

    std::ofstream ofs(path);
    ofs << getJSONString(results);
    std::cout << Color::CYAN << "  [JSON] Report written -> " << path << Color::RESET << "\n";
    return path;
}

// ─── CSV ──────────────────────────────────────────────────────────────────────

std::string ReportGenerator::writeCSV(const std::vector<FileInfo>& results,
                                       const std::string& outDir) {
    ensureDir(outDir);
    std::string path = outDir + "/scan_" + timestamp() + ".csv";

    std::ofstream ofs(path);
    // Header
    ofs << "File,Path,Extension,Size(bytes),Entropy,EntropyBand,RiskScore,"
           "Classification,Hidden,DoubleExtension,Flags\n";

    for (const auto& fi : results) {
        // Escape quotes in paths
        auto esc = [](std::string s) -> std::string {
            std::string out = "\"";
            for (char c : s) {
                if (c == '"') out += '"';
                out += c;
            }
            out += '"';
            return out;
        };

        std::string flagList;
        for (const auto& f : fi.flags) {
            if (!flagList.empty()) flagList += "; ";
            flagList += f.reason;
        }

        ofs << esc(fi.filename)     << ","
            << esc(fi.filepath)     << ","
            << fi.extension         << ","
            << fi.size              << ","
            << std::fixed << std::setprecision(4) << fi.entropy << ","
            << EntropyAnalyzer::band(fi.entropy)  << ","
            << fi.riskScore         << ","
            << riskLevelToString(fi.riskLevel) << ","
            << (fi.isHidden    ? "yes" : "no") << ","
            << (fi.hasDoubleExt? "yes" : "no") << ","
            << esc(flagList)        << "\n";
    }

    std::cout << Color::CYAN << "  [CSV]  Report written → " << path << Color::RESET << "\n";
    return path;
}

} // namespace mscanner
