#include "EntropyAnalyzer.h"
#include <fstream>
#include <array>
#include <cmath>
#include <stdexcept>

namespace mscanner {

double EntropyAnalyzer::calculate(const std::string& filepath) {
    // Open in binary mode – we measure byte-level distribution
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return 0.0;

    std::array<long long, 256> freq{};
    freq.fill(0);

    long long total = 0;
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        auto n = file.gcount();
        for (std::streamsize i = 0; i < n; ++i) {
            ++freq[static_cast<unsigned char>(buf[i])];
        }
        total += n;
    }

    if (total == 0) return 0.0;

    // H = -Σ p(x) * log2(p(x))
    double entropy = 0.0;
    for (int b = 0; b < 256; ++b) {
        if (freq[b] == 0) continue;
        double p = static_cast<double>(freq[b]) / static_cast<double>(total);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::string EntropyAnalyzer::band(double e) {
    if (e < 4.0) return "Low";
    if (e < 6.0) return "Medium";
    if (e < 7.5) return "High";
    return "Very High";
}

int EntropyAnalyzer::riskPoints(double e) {
    /*
     * Scoring rationale:
     *  Very High (≥7.5): typical of UPX-packed, encrypted, or obfuscated code → +40
     *  High      (≥6.0): compressed, some packed formats                       → +20
     *  Medium    (≥4.0): normal binary executables, PDFs                       → +5
     *  Low       (<4.0): plaintext source, scripts                             → +0
     */
    if (e >= 7.5) return 40;
    if (e >= 6.0) return 20;
    if (e >= 4.0) return  5;
    return 0;
}

} // namespace mscanner
