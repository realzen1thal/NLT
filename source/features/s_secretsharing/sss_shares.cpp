#include "sss_shares.h"
#include <sodium/sodium.h>
#include <fstream>
#include <filesystem>
#include <map>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace fs = std::filesystem;

namespace {
    constexpr char SSS_MAGIC[4] = { 'N', 'L', 'T', 'S' };

    void write_u32le(std::ostream& o, uint32_t v) {
        unsigned char b[4]; memcpy(b, &v, 4); o.write((char*)b, 4);
    }
    uint32_t read_u32le(std::istream& i) {
        unsigned char b[4]; i.read((char*)b, 4);
        if (!i) return 0;
        uint32_t v; memcpy(&v, b, 4); return v;
    }

    std::string to_hex(const unsigned char* data, size_t len) {
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(hex[data[i] >> 4]);
            out.push_back(hex[data[i] & 0x0F]);
        }
        return out;
    }
} // namespace

// ─── --sss flag validation ("--sss X-Y") ─────────────────────────
SssConfig parse_sss_spec(const std::string& spec) {
    if (spec.empty())
        throw std::runtime_error("--sss requires a value in the form N-K (e.g. --sss 5-3)");

    auto dash = spec.find('-');
    if (dash == std::string::npos || dash == 0 || dash == spec.size() - 1)
        throw std::runtime_error("--sss value must be in the form N-K (e.g. --sss 5-3)");

    std::string n_str = spec.substr(0, dash);
    std::string k_str = spec.substr(dash + 1);

    for (char c : n_str) if (!isdigit((unsigned char)c))
        throw std::runtime_error("--sss N-K: N must be a positive integer");
    for (char c : k_str) if (!isdigit((unsigned char)c))
        throw std::runtime_error("--sss N-K: K must be a positive integer");

    long n = std::stol(n_str);
    long k = std::stol(k_str);

    if (n < 2 || k < 2)
        throw std::runtime_error(
            "--sss refused: N-K of 1-1 (or anything below 2-2) provides no real "
            "secret splitting and defeats the purpose of SSS.");
    if (k > n)
        throw std::runtime_error("--sss refused: threshold K cannot exceed total shares N");
    if (n > 255)
        throw std::runtime_error("--sss refused: N cannot exceed 255 (GF(256) share-index limit)");

    return SssConfig{ (uint8_t)n, (uint8_t)k };
}

std::string generate_sss_password() {
    unsigned char raw[32];
    randombytes_buf(raw, sizeof(raw));
    std::string pw = to_hex(raw, sizeof(raw));
    sodium_memzero(raw, sizeof(raw));
    return pw;
}

void write_sss_share_file(const std::string& base_path, const SssShareFile& file) {
    std::string out_path = base_path + ".share" + std::to_string(file.share.index) + ".nlt";
    std::ofstream f(out_path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot create share file: " + out_path);

    f.write(SSS_MAGIC, 4);
    f.write((const char*)file.secret_id.data(), SSS_SECRET_ID_LEN);
    f.write((const char*)&file.k, 1);
    f.write((const char*)&file.share.index, 1);
    write_u32le(f, (uint32_t)file.share.data.size());
    f.write((const char*)file.share.data.data(), file.share.data.size());

    if (!f) throw std::runtime_error("Failed writing share file: " + out_path);
}

std::optional<SssShareFile> read_sss_share_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;

    char magic[4];
    f.read(magic, 4);
    if (!f || memcmp(magic, SSS_MAGIC, 4) != 0) return std::nullopt;

    SssShareFile out{};
    f.read((char*)out.secret_id.data(), SSS_SECRET_ID_LEN);
    if (!f) return std::nullopt;

    f.read((char*)&out.k, 1);
    f.read((char*)&out.share.index, 1);
    if (!f) return std::nullopt;

    uint32_t len = read_u32le(f);
    if (!f || len == 0 || len > (64 * 1024 * 1024)) return std::nullopt; // sanity bound

    out.share.data.resize(len);
    f.read((char*)out.share.data.data(), len);
    if (!f) return std::nullopt;

    return out;
}

std::vector<SssShareFile> collect_sss_shares_from_dir(const std::string& dir) {
    std::map<std::string, std::vector<SssShareFile>> by_secret_id;

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".nlt") continue;

        auto parsed = read_sss_share_file(entry.path().string());
        if (!parsed) continue; // not a valid share file, skip silently

        std::string id_hex = to_hex(parsed->secret_id.data(), SSS_SECRET_ID_LEN);
        by_secret_id[id_hex].push_back(*parsed);
    }

    if (by_secret_id.empty())
        throw std::runtime_error("No valid .nlt share files found in: " + dir);

    // Pick the secret_id group with the most shares (most likely to
    // meet the threshold); if there's a tie, this picks one
    // deterministically via map ordering.
    auto best = std::max_element(by_secret_id.begin(), by_secret_id.end(),
        [](const auto& a, const auto& b) { return a.second.size() < b.second.size(); });

    return best->second;
}