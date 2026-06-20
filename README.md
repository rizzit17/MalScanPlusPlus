# MalScan++

> A high-performance, static malware detection engine built in C++20.

MalScan++ is a powerful command-line utility designed to analyze files and directories for malicious indicators using purely static heuristics. It safely evaluates file metadata, calculates Shannon entropy to detect packed payloads, and identifies obfuscation techniques without ever executing the target files.

## 🌟 Features

* **Recursive Directory Scanning**: High-speed filesystem traversal with robust exception handling for protected OS directories.
* **Shannon Entropy Analysis**: Accurately detects packed or encrypted payloads by mathematically evaluating byte randomness and distribution.
* **Heuristic Risk Engine**: Pluggable Strategy Pattern architecture evaluating files against multiple threat vectors:
  * Suspicious extensions (`.scr`, `.vbs`, `.ps1`)
  * Double-extension spoofing (`invoice.pdf.exe`)
  * Obfuscated hidden directories/files
  * Threat-actor keywords (`keygen`, `payload`, `injector`)
  * Evasion-padded large executables
* **Categorical Risk Scoring**: Automatically classifies files as `SAFE`, `SUSPICIOUS`, or `HIGH_RISK`.
* **Standardized Reporting**: Exports analysis results to JSON and CSV formats for SIEM integration.
* **ANSI Colored CLI**: Beautiful, readable terminal output.

## 📸 Screenshots

*(Replace these placeholders with actual screenshots once the project is built)*

1. **Terminal Output**
   `[Screenshot of the ANSI colored terminal scanning a directory, highlighting a HIGH_RISK file in red.]`
2. **JSON Export**
   `[Screenshot of the generated JSON report showing the calculated entropy and score.]`

## 🏗️ Architecture

MalScan++ employs a highly modular architecture emphasizing the **Strategy Pattern** and **Dependency Injection**. The core `RiskEngine` dynamically loads `IAnalyzer` instances, allowing developers to seamlessly add new detection algorithms without modifying existing engine logic.

Please refer to the `docs/` folder or the `MalScan_Blueprint.md` for complete class diagrams and data flow diagrams.

## 🚀 Installation & Build Guide

### Prerequisites
* C++20 compatible compiler (MSVC, GCC 11+, Clang 14+)
* [CMake](https://cmake.org/) (v3.20+)
* [vcpkg](https://vcpkg.io/) (C++ Package Manager)

### Build Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/MalScan-Plus-Plus.git
   cd MalScan-Plus-Plus
   ```

2. **Configure with CMake & vcpkg**
   ```bash
   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake
   ```

3. **Build the project**
   ```bash
   cmake --build build --config Release
   ```

## 💻 Usage

Run the scanner by providing a target directory or file:

```bash
# Scan a specific directory
./scanner "C:\Users\Target\Downloads"

# Scan with JSON output
./scanner "/home/user/downloads" --report json
```

## 🔮 Future Enhancements

* **YARA Rule Integration**: Support for industry-standard pattern matching.
* **PE/ELF Header Analysis**: Deep inspection of Import Address Tables and section permissions.
* **SHA256 IOC Matching**: Integration with SQLite to cross-reference known malicious hashes.
* **Machine Learning Classification**: Replacing the static scoring engine with a trained Random Forest classifier.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
