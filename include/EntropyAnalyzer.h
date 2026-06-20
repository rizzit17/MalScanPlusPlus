#pragma once
#include <string>

namespace mscanner {

/*
 * Shannon entropy: H = -Σ p(x) * log2(p(x))
 *
 * Why it matters in malware analysis:
 *  - Normal text/code:         entropy ≈ 3.5 – 5.5
 *  - Compressed archives:      entropy ≈ 7.0 – 7.9
 *  - Packed/obfuscated PE:     entropy ≈ 7.5 – 8.0
 *  - AES-encrypted payload:    entropy ≈ 7.99 – 8.0
 *
 * Malware families (UPX, Themida, ASPack) compress their code sections
 * to evade signature detection. This compression produces very high entropy.
 * Ransomware also produces high entropy on already-encrypted files.
 */
class EntropyAnalyzer {
public:
    // Reads file in binary mode, returns Shannon entropy in [0, 8]
    static double calculate(const std::string& filepath);

    // Human-readable band label
    static std::string band(double entropy);

    // Risk points contributed by entropy alone
    static int riskPoints(double entropy);
};

} // namespace mscanner
