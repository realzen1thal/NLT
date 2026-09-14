#pragma once
#include "algorithm/sss.h"
#include <string>
#include <vector>
#include <optional>
#include <array>
#include <cstdint>

// ─── --sss flag validation (policy, not math) ───────────────────
//
// Validates n/k values from a "--sss X-Y" flag. Throws with a clear,
// user-facing message on invalid input: empty/garbage input, 1-1 (or
// anything below 2-2), K > N, or N > 255. The underlying math in
// s_secretsharing.h has no opinion on any of these rules — this is
// where NLT's specific policy about what's an acceptable split lives.
SssConfig parse_sss_spec(const std::string& spec);

// ─── SSS share-file format (.nlt share files) ──────────────────
//
// Kept deliberately minimal, but a share file still needs a FEW
// bytes beyond the raw share value, or two things break:
//   - "point at a folder, figure out which files are shares" mode
//     (--sss-dir) has no way to recognize a share file at all
//   - shares from two different encrypt runs sitting in the same
//     folder can't be told apart, so combining them would silently
//     produce garbage instead of a clear error
//
// So each file carries: a 4-byte magic marker, the secret's random
// ID (so mismatched shares are rejected), the threshold K, this
// share's index, and the share bytes themselves. Nothing about the
// original file, its name, or any other metadata.
//
// Layout (little-endian):
//   magic       4 bytes   "NLTS"
//   secret_id  16 bytes   random, generated once per encrypt call
//   k           1 byte    threshold required to reconstruct
//   index       1 byte    this share's index (1..n)
//   share_len   4 byte    length of share data that follows (uint32)
//   share_data  N bytes

constexpr size_t SSS_SECRET_ID_LEN = 16;

struct SssShareFile {
    std::array<uint8_t, SSS_SECRET_ID_LEN> secret_id;
    uint8_t k;
    SssShare share;
};

// Generates a strong random password (32 raw bytes, hex-encoded to a
// 64-character string) suitable for use as the Argon2id input. This
// is what gets split via SSS — never a user-supplied password.
std::string generate_sss_password();

// Writes one share to disk as `<base_path>.share<index>.nlt`.
void write_sss_share_file(const std::string& base_path, const SssShareFile& file);

// Reads a single .nlt share file. Returns nullopt (does not throw) if
// the file doesn't look like a valid share file at all — callers
// scanning a directory should skip such files rather than fail.
std::optional<SssShareFile> read_sss_share_file(const std::string& path);

// Scans `dir` for files matching *.nlt, reads each, and groups them by
// secret_id. Returns the group with the most shares matching a single
// secret_id (this is how --sss-dir figures out "which shares belong
// together" without the user needing to list them explicitly).
std::vector<SssShareFile> collect_sss_shares_from_dir(const std::string& dir);