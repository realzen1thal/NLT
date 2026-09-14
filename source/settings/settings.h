#pragma once
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

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

    // --sss N-K (encrypt only): split the (auto-generated) password
    // into N shares, K of which are required to reconstruct it.
    // Mutually exclusive with a user-supplied password.
    std::optional<std::string> sss_spec;

    // Decrypt-side share gathering (mutually exclusive with each other):
    std::vector<std::string> sss_share_files; // --sss-shares a.nlt b.nlt c.nlt
    std::optional<std::string> sss_share_dir; // --sss-dir ./shares/
};

// Parses argv into CliOptions. Returns false (and leaves options
// unspecified) if the arguments are malformed / incomplete.
bool parse_cli(int argc, char** argv, CliOptions& out);

void print_usage(const char* prog);