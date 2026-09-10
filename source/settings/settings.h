#pragma once
#include <cstdint>
#include <string>

// ─── Adaptive Buffer Sizing ─────────────────────────────────
struct BufferConfig {
    size_t chunk_size;
    const char* label;
};

// Picks a chunk size scaled to the file size (16 KB .. 64 MB).
BufferConfig get_optimal_buffer(uint64_t file_size);

// ─── CLI Options ─────────────────────────────────────────────
enum class Command { None, Encrypt, Decrypt };

struct CliOptions {
    Command command = Command::None;
    std::string filepath;
    bool no_compression = false; // --nocompression
};

// Parses argv into CliOptions. Returns false (and leaves options
// unspecified) if the arguments are malformed / incomplete.
bool parse_cli(int argc, char** argv, CliOptions& out);

void print_usage(const char* prog);