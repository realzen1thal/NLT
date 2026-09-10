#include "settings.h"
#include <cstring>
#include <iostream>
#include <algorithm>

BufferConfig get_optimal_buffer(uint64_t file_size) {
    constexpr uint64_t KB = 1024ULL;
    constexpr uint64_t MB = 1024ULL * KB;
    constexpr uint64_t GB = 1024ULL * MB;

    if (file_size < 1 * MB)        return { 16 * KB,  "16 KB" };
    if (file_size < 10 * MB)       return { 64 * KB,  "64 KB" };
    if (file_size < 100 * MB)      return { 256 * KB, "256 KB" };
    if (file_size < 1 * GB)        return { 1 * MB,   "1 MB" };
    if (file_size < 10 * GB)       return { 4 * MB,   "4 MB" };
    if (file_size < 100 * GB)      return { 16 * MB,  "16 MB" };
    /* >= 100 GB */                return { 64 * MB,  "64 MB" };
}

void print_usage(const char* prog) {
    std::cerr << "Usage:\n  " << prog << " encrypt <file> [--nocompression]\n"
        << "  " << prog << " decrypt <file>\n\n"
        << "Password:\n"
        << "  Interactive terminal -> masked prompt.\n"
        << "  Piped/redirected stdin -> password read from stdin, e.g.:\n"
        << "    cat secret.txt | " << prog << " encrypt file.bin\n"
        << "    " << prog << " encrypt file.bin <<< \"$MY_PASSWORD\"\n";
}

bool parse_cli(int argc, char** argv, CliOptions& out) {
    if (argc < 3) return false;

    std::string cmd = argv[1];
    if (cmd == "encrypt") out.command = Command::Encrypt;
    else if (cmd == "decrypt") out.command = Command::Decrypt;
    else return false;

    out.filepath = argv[2];

    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--nocompression")) {
            out.no_compression = true;
        }
    }
    return true;
}