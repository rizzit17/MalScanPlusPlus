#include "Scanner.h"
#include "ReportGenerator.h"
#include "Utils.h"
#include <iostream>
#include <httplib.h>

using namespace mscanner;

void startServer(int port) {
    httplib::Server svr;

    // Serve static files from the public folder
    svr.set_mount_point("/", "./public");

    // Define API endpoint
    svr.Get("/api/scan", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("path")) {
            res.status = 400;
            res.set_content("{\"error\": \"Missing path parameter\"}", "application/json");
            return;
        }

        std::string targetPath = req.get_param_value("path");
        
        try {
            Scanner scanner(false); // Ensure quiet CLI output so web threads don't spam terminal
            auto results = scanner.scan(targetPath);
            std::string jsonReport = ReportGenerator::getJSONString(results);
            res.set_content(jsonReport, "application/json");
            res.set_header("Access-Control-Allow-Origin", "*");
        } catch (const std::exception& e) {
            res.status = 500;
            std::string err = "{\"error\": \""; err += e.what(); err += "\"}";
            res.set_content(err, "application/json");
        }
    });

    std::cout << Color::CYAN << Color::BOLD
              << "\n+------------------------------------------------------+\n"
              << "|         MalScan++ Web Server Initialized             |\n"
              << "+------------------------------------------------------+\n"
              << Color::RESET;
    std::cout << Color::GREEN << "Listening on http://localhost:" << port << Color::RESET << "\n";
    std::cout << "Press Ctrl+C to stop the server.\n\n";

    svr.listen("0.0.0.0", port);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <directory_path> [--json] [--csv] [-v|--verbose]\n";
        std::cerr << "   or: " << argv[0] << " --server [port]\n";
        return 1;
    }

    std::string arg1 = argv[1];

    if (arg1 == "--server") {
        int port = 8080;
        if (argc >= 3) {
            port = std::stoi(argv[2]);
        }
        startServer(port);
        return 0;
    }

    // CLI Mode
    std::string path = arg1;
    bool jsonOutput = false;
    bool csvOutput = false;
    bool verbose = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") jsonOutput = true;
        if (arg == "--csv") csvOutput = true;
        if (arg == "-v" || arg == "--verbose") verbose = true;
    }

    Scanner scanner(verbose);
    try {
        auto results = scanner.scan(path);

        if (jsonOutput) {
            ReportGenerator::writeJSON(results);
        }
        if (csvOutput) {
            ReportGenerator::writeCSV(results);
        }

    } catch (const std::exception& e) {
        std::cerr << Color::RED << "Fatal error: " << e.what() << Color::RESET << "\n";
        return 1;
    }

    return 0;
}
