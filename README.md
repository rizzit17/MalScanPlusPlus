<div align="center">
  <h1>🛡️ MalScan++</h1>
  <p><b>A High-Performance, Dual-Execution Static Malware Analysis Engine</b></p>
  
  [![C++20](https://img.shields.io/badge/C++-20-blue.svg?style=flat-square&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/compiler_support)
  [![CMake](https://img.shields.io/badge/CMake-3.20+-success.svg?style=flat-square&logo=cmake)](https://cmake.org/)
  [![License](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
</div>

---

**MalScan++** is a powerful command-line utility and web-dashboard designed to analyze files and directories for malicious indicators using purely static heuristics. It safely evaluates file metadata, calculates Shannon entropy to detect packed payloads, and identifies obfuscation techniques without ever executing the target files.

## 🌟 Key Features

* **Dual Execution Modes**: Run headless scans via the Terminal, or launch the built-in HTTP server to access the premium Web Dashboard.
* **Shannon Entropy Analysis**: Accurately detects packed, compressed, or encrypted payloads by mathematically evaluating byte randomness (`H = -Σ p(x) log2(p(x))`) in constant $O(1)$ memory.
* **Heuristic Risk Engine**: Pluggable architecture evaluating files against multiple threat vectors:
  * Suspicious extensions (`.scr`, `.vbs`, `.ps1`)
  * Double-extension spoofing (`invoice.pdf.exe`)
  * Obfuscated hidden directories/files
  * Threat-actor keywords (`keygen`, `payload`, `injector`)
  * Evasion-padded large executables (>50MB)
* **Categorical Risk Scoring**: Automatically classifies files as `SAFE`, `SUSPICIOUS`, or `HIGH_RISK`.
* **Standardized Reporting**: Exports analysis results to JSON and CSV formats for external SIEM integration.

## 🏗️ Architecture

MalScan++ is built with strict adherence to modern software engineering principles:
* **Strategy Pattern**: The heuristic analysis pipeline uses pluggable components allowing easy integration of future detection algorithms.
* **Memory Efficiency**: Binary file streams are processed in 8KB chunks, ensuring that scanning massive gigabyte-sized files requires zero RAM overhead.
* **Native REST API**: Integrates `cpp-httplib` for native thread-safe HTTP routing without relying on bulky external frameworks.

---

## 🚀 Installation & Build

This project relies on `vcpkg` for dependency management (`nlohmann-json`, `cxxopts`, `cpp-httplib`, `gtest`).

### Prerequisites
* Visual Studio 2022 (with Desktop Development C++ Workload)
* CMake (3.20+)
* [vcpkg](https://vcpkg.io/en/getting-started.html) installed and bootstrapped.

### Build Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YourUsername/MalScanPlusPlus.git
   cd MalScanPlusPlus
   ```

2. **Configure CMake (Replace the vcpkg toolchain path):**
   ```bash
   cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake"
   ```

3. **Compile in Release Mode:**
   ```bash
   cmake --build build --config Release
   ```

---

## 💻 Usage

### 1. Terminal Mode (CLI)
Run the executable directly against any file or folder. Use the `-v` flag to see exact heuristic points awarded per file.
```bash
.\build\Release\scanner.exe "C:\Path\To\Scan" -v --json --csv
```

### 2. Web Dashboard Mode
MalScan++ comes with a built-in HTTP server that serves a modern graphical dashboard.
```bash
.\build\Release\scanner.exe --server 8080
```
*Open `http://localhost:8080` in your web browser to access the scanning UI.*

---

## 📸 Screenshots

*(Add screenshots of your project here to make the repository pop!)*

* **CLI Output:** `![Terminal Placeholder]()`
* **Web Dashboard:** `![Dashboard Placeholder]()`

---

## ⚠️ Disclaimer
MalScan++ is designed exclusively for **static** heuristic analysis. It is an educational cybersecurity tool and is not a replacement for dynamic sandboxing, EDRs, or traditional signature-based Antivirus engines. It does not execute or sandbox malware. 

## 📝 License
Distributed under the MIT License.
