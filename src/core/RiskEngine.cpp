#include "RiskEngine.h"
#include "EntropyAnalyzer.h"
#include "Utils.h"
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace mscanner {

// ─── Static data tables ───────────────────────────────────────────────────────

const std::unordered_map<std::string, int>& RiskEngine::suspiciousExtensions() {
    /*
     * Why these extensions are risky:
     *  .exe / .dll  – Windows PE executables / dynamic libraries; direct code execution
     *  .scr         – Screen savers; execute as PE files, historically used by worms
     *  .bat / .cmd  – Windows batch scripts; trivial to weaponize
     *  .vbs         – VBScript; used by ILOVEYOU worm, macros, downloader scripts
     *  .ps1         – PowerShell; near-unlimited system access, fileless malware vector
     *  .js          – JavaScript (Windows Script Host); used by Nemucod downloader
     *  .jar         – Java Archives; cross-platform payload (Adwind RAT)
     *  .msi         – Windows installer packages; installs arbitrary payloads silently
     *  .hta         – HTML Application; runs as trusted by mshta.exe, bypasses some AV
     *  .com         – Legacy DOS executables; still run on modern Windows
     */
    static const std::unordered_map<std::string, int> table = {
        {".exe", 10}, {".dll", 10}, {".scr", 20}, {".bat", 15},
        {".cmd", 15}, {".vbs", 20}, {".ps1", 20}, {".js",  15},
        {".jar", 10}, {".msi", 10}, {".hta", 20}, {".com", 15},
        {".pif", 20}, {".lnk", 10}
    };
    return table;
}

const std::vector<std::string>& RiskEngine::suspiciousKeywords() {
    /*
     * Keywords found in malware filenames:
     *  crack/patch/keygen – software piracy tools often bundled with trojans
     *  loader/inject      – malware loading/DLL injection utilities
     *  stealer/rat        – credential stealers, Remote Access Trojans
     *  miner              – cryptominer droppers (XMRig, etc.)
     *  payload/backdoor   – self-explanatory offensive tools
     *  dropper/downloader – first-stage malware
     *  exploit/bypass     – security bypass utilities
     */
    static const std::vector<std::string> kw = {
        "crack","keygen","hack","patch","loader","inject","stealer",
        "rat","miner","payload","backdoor","dropper","downloader",
        "exploit","bypass","cheat","nulled","warez","activator","unlocker"
    };
    return kw;
}

const std::vector<std::string>& RiskEngine::executableExtensions() {
    static const std::vector<std::string> execs = {
        ".exe",".dll",".scr",".com",".pif",".msi",".jar",".hta"
    };
    return execs;
}

// ─── Orchestration ────────────────────────────────────────────────────────────

void RiskEngine::evaluate(FileInfo& fi) const {
    checkExtension      (fi);
    checkDoubleExtension(fi);
    checkKeywords       (fi);
    checkHidden         (fi);
    checkLargeExecutable(fi);
    checkEntropy        (fi);
    finalizeLevel       (fi);
}

// ─── Individual checks ────────────────────────────────────────────────────────

void RiskEngine::checkExtension(FileInfo& fi) const {
    const auto& table = suspiciousExtensions();
    auto it = table.find(fi.extension);
    if (it != table.end()) {
        fi.isSuspiciousExt = true;
        fi.riskScore += it->second;
        fi.flags.push_back({"Suspicious extension: " + fi.extension, it->second});
    }
}

void RiskEngine::checkDoubleExtension(FileInfo& fi) const {
    /*
     * Double extension trick:
     *  "invoice.pdf.exe" – Windows hides known extensions by default.
     *  The user sees "invoice.pdf" and believes it's a document.
     *  Clicking executes the .exe.  Used by Melissa, ILOVEYOU, and countless
     *  phishing campaigns.
     *
     * Detection: stem of the filename (everything before last extension)
     * itself has a known extension.
     */
    namespace fs = std::filesystem;
    fs::path p(fi.filename);
    std::string stem = p.stem().string(); // e.g. "invoice.pdf" from "invoice.pdf.exe"
    fs::path inner(stem);
    std::string innerExt = Utils::toLower(inner.extension().string());

    // List of benign-looking extensions used as decoys
    static const std::vector<std::string> decoys = {
        ".pdf",".doc",".docx",".xls",".xlsx",".jpg",".jpeg",
        ".png",".gif",".mp3",".mp4",".txt",".csv",".zip"
    };
    for (const auto& d : decoys) {
        if (innerExt == d) {
            fi.hasDoubleExt = true;
            fi.riskScore += 30;
            fi.flags.push_back({"Double extension detected: " + innerExt + fi.extension, 30});
            return;
        }
    }
}

void RiskEngine::checkKeywords(FileInfo& fi) const {
    std::string nameLower = Utils::toLower(fi.filename);
    for (const auto& kw : suspiciousKeywords()) {
        if (nameLower.find(kw) != std::string::npos) {
            if (!fi.hasKeyword) {
                fi.hasKeyword = true;
                fi.riskScore += 25;
                fi.flags.push_back({"Suspicious keyword in filename: \"" + kw + "\"", 25});
            } else {
                // Multiple keywords = additional penalty
                fi.riskScore += 10;
                fi.flags.push_back({"Additional keyword: \"" + kw + "\"", 10});
            }
        }
    }
}

void RiskEngine::checkHidden(FileInfo& fi) const {
    /*
     * Hidden files on Linux start with '.'.
     * On Windows the HIDDEN attribute is set via filesystem API.
     * Malware hides itself to avoid casual inspection.
     */
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(fi.filepath.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_HIDDEN)) {
        fi.isHidden = true;
        fi.riskScore += 10;
        fi.flags.push_back({"Hidden file (Windows attribute)", 10});
    }
#else
    // POSIX: leading dot
    if (!fi.filename.empty() && fi.filename[0] == '.') {
        fi.isHidden = true;
        fi.riskScore += 10;
        fi.flags.push_back({"Hidden file (dotfile)", 10});
    }
#endif
}

void RiskEngine::checkLargeExecutable(FileInfo& fi) const {
    /*
     * Legitimate executables are rarely >50 MB.
     * Large executables may be:
     *  - Bundled with a large payload (dropper + data)
     *  - Self-extracting archives containing additional malware
     *  - Packed with huge junk sections to confuse size-based heuristics
     */
    constexpr uintmax_t THRESHOLD = 50ULL * 1024 * 1024; // 50 MB
    const auto& execs = executableExtensions();
    bool isExec = std::any_of(execs.begin(), execs.end(),
                              [&](const std::string& e){ return fi.extension == e; });
    if (isExec && fi.size > THRESHOLD) {
        fi.isLargeExec = true;
        fi.riskScore += 15;
        fi.flags.push_back({"Large executable (>" + Utils::humanSize(THRESHOLD) + ")", 15});
    }
}

void RiskEngine::checkEntropy(FileInfo& fi) const {
    try {
        fi.entropy = EntropyAnalyzer::calculate(fi.filepath);
        int pts    = EntropyAnalyzer::riskPoints(fi.entropy);
        if (pts > 0) {
            fi.riskScore += pts;
            fi.flags.push_back({
                "High entropy (" + std::to_string(fi.entropy).substr(0,5) +
                " - " + EntropyAnalyzer::band(fi.entropy) + ")", pts
            });
        }
    } catch (...) {
        // Unreadable file – skip entropy
    }
}

void RiskEngine::finalizeLevel(FileInfo& fi) const {
    if      (fi.riskScore >= 60) fi.riskLevel = RiskLevel::HIGH_RISK;
    else if (fi.riskScore >= 30) fi.riskLevel = RiskLevel::SUSPICIOUS;
    else                         fi.riskLevel = RiskLevel::SAFE;
}

} // namespace mscanner
