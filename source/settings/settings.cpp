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
    std::cerr << "Usage:\n"
        << "  " << prog << " encrypt <file> [--nocompression] [--sss N-K]\n"
        << "  " << prog << " decrypt <file> [--sss-shares f1.nlt f2.nlt ...] [--sss-dir <folder>]\n\n"
        << "Password:\n"
        << "  Interactive terminal -> masked prompt.\n"
        << "  Piped/redirected stdin -> password read from stdin, e.g.:\n"
        << "    cat secret.txt | " << prog << " encrypt file.bin\n"
        << "    " << prog << " encrypt file.bin <<< \"$MY_PASSWORD\"\n\n"
        << "Shamir Secret Sharing (--sss N-K):\n"
        << "  Generates a strong random password (no prompt/stdin used) and\n"
        << "  splits it into N shares, K of which are required to reconstruct it.\n"
        << "  Writes N files: <file>.share1.nlt .. <file>.shareN.nlt\n"
        << "  Example: " << prog << " encrypt test.txt --sss 5-3 --nocompression\n\n"
        << "  To decrypt an SSS-protected file, provide >= K shares via\n"
        << "  --sss-shares (list files) or --sss-dir (a folder containing them).\n";
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
        else if (!strcmp(argv[i], "--sss") && i + 1 < argc) {
            out.sss_spec = argv[++i];
        }
        else if (!strcmp(argv[i], "--sss-dir") && i + 1 < argc) {
            out.sss_share_dir = argv[++i];
        }
        else if (!strcmp(argv[i], "--sss-shares")) {
            // Consumes all following non-flag args as share file paths,
            // stopping at the next token that looks like a flag (starts
            // with "--") or at the end of argv.
            while (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0) {
                out.sss_share_files.push_back(argv[++i]);
            }
        }
    }
    return true;
}