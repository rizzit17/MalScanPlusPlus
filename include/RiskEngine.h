#pragma once
#include "FileInfo.h"
#include <unordered_map>
#include <vector>
#include <string>

namespace mscanner {

class RiskEngine {
public:
    void evaluate(FileInfo& fi) const;

private:
    static const std::unordered_map<std::string, int>& suspiciousExtensions();
    static const std::vector<std::string>& suspiciousKeywords();
    static const std::vector<std::string>& executableExtensions();

    void checkExtension(FileInfo& fi) const;
    void checkDoubleExtension(FileInfo& fi) const;
    void checkKeywords(FileInfo& fi) const;
    void checkHidden(FileInfo& fi) const;
    void checkLargeExecutable(FileInfo& fi) const;
    void checkEntropy(FileInfo& fi) const;
    void finalizeLevel(FileInfo& fi) const;
};

} // namespace mscanner
