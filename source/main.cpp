#include "common.h"
#include "settings/settings.h"
#include "logic/encrypt/encrypt.h"
#include "logic/decrypt/decrypt.h"
#include "features/s_secretsharing/algorithm/sss.h"
#include "features/s_secretsharing/sss_shares.h"

#include <sodium/sodium.h>
#include <iostream>

namespace {

    // Generates a random 16-byte secret_id linking all shares from one
    // encrypt run together, so decrypt can tell them apart from shares
    // belonging to a different file/run sitting in the same folder.
    std::array<uint8_t, SSS_SECRET_ID_LEN> generate_secret_id() {
        std::array<uint8_t, SSS_SECRET_ID_LEN> id{};
        randombytes_buf(id.data(), id.size());
        return id;
    }

    // Encrypt-side: generate a random password, run the normal encrypt
    // path with it, then split the password via SSS and write N share
    // files next to the encrypted output.
    void encrypt_with_sss(const CliOptions& opt) {
        SssConfig cfg = parse_sss_spec(*opt.sss_spec); // throws on 1-1, N<2, K>N, etc.

        std::string pw = generate_sss_password();

        do_encrypt(opt.filepath, pw, !opt.no_compression);

        std::vector<uint8_t> secret_bytes(pw.begin(), pw.end());
        auto shares = sss_split(secret_bytes, cfg);
        auto secret_id = generate_secret_id();

        for (const auto& share : shares) {
            SssShareFile file{ secret_id, cfg.k, share };
            write_sss_share_file(opt.filepath, file);
        }

        sodium_memzero(secret_bytes.data(), secret_bytes.size());
        secure_wipe(&pw[0], pw.size());

        std::cout << "[+] SSS: wrote " << (int)cfg.n << " share files "
            << "(" << (int)cfg.k << " required to reconstruct):\n";
        for (const auto& share : shares) {
            std::cout << "    " << opt.filepath << ".share" << (int)share.index << ".nlt\n";
        }
    }

    // Decrypt-side: gather shares from --sss-shares and/or --sss-dir,
    // reconstruct the password, then run the normal decrypt path with it.
    void decrypt_with_sss(const CliOptions& opt) {
        std::vector<SssShareFile> gathered;

        for (const auto& path : opt.sss_share_files) {
            auto f = read_sss_share_file(path);
            if (!f) throw std::runtime_error("Not a valid share file: " + path);
            gathered.push_back(*f);
        }

        if (opt.sss_share_dir) {
            auto from_dir = collect_sss_shares_from_dir(*opt.sss_share_dir);
            gathered.insert(gathered.end(), from_dir.begin(), from_dir.end());
        }

        if (gathered.empty())
            throw std::runtime_error("No SSS share files provided (--sss-shares / --sss-dir)");

        // All gathered shares must belong to the same secret and agree on
        // threshold K, and we need at least K of them.
        const auto& secret_id = gathered[0].secret_id;
        uint8_t k = gathered[0].k;
        for (const auto& f : gathered) {
            if (f.secret_id != secret_id)
                throw std::runtime_error("Gathered share files belong to different secrets - mismatched shares");
            if (f.k != k)
                throw std::runtime_error("Gathered share files disagree on threshold K - corrupted or mismatched shares");
        }
        if (gathered.size() < k)
            throw std::runtime_error("Not enough shares: have " + std::to_string(gathered.size()) +
                ", need " + std::to_string((int)k));

        std::vector<SssShare> raw_shares;
        for (size_t i = 0; i < (size_t)k; ++i) raw_shares.push_back(gathered[i].share);

        auto secret_bytes = sss_combine(raw_shares);
        std::string pw(secret_bytes.begin(), secret_bytes.end());
        sodium_memzero(secret_bytes.data(), secret_bytes.size());

        try {
            do_decrypt(opt.filepath, pw);
        }
        catch (...) {
            secure_wipe(&pw[0], pw.size());
            throw;
        }
        secure_wipe(&pw[0], pw.size());
    }

} // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) { std::cerr << "sodium fail\n"; return 1; }

    CliOptions opt;
    if (!parse_cli(argc, argv, opt)) {
        print_usage(argv[0]);
        return 1;
    }

    bool using_sss = opt.sss_spec.has_value() ||
        !opt.sss_share_files.empty() ||
        opt.sss_share_dir.has_value();

    try {
        if (opt.command == Command::Encrypt && opt.sss_spec) {
            encrypt_with_sss(opt);
        }
        else if (opt.command == Command::Decrypt &&
            (!opt.sss_share_files.empty() || opt.sss_share_dir)) {
            decrypt_with_sss(opt);
        }
        else if (using_sss) {
            // e.g. --sss-shares passed to encrypt, or --sss passed to decrypt
            std::cerr << "Error: SSS flags don't match this command "
                "(--sss is encrypt-only, --sss-shares/--sss-dir are decrypt-only)\n";
            return 1;
        }
        else {
            // Normal, non-SSS path: unchanged from before.
            std::string pw = resolve_password();
            if (pw.empty()) { std::cerr << "Empty password\n"; return 1; }

            if (opt.command == Command::Encrypt)
                do_encrypt(opt.filepath, pw, !opt.no_compression);
            else if (opt.command == Command::Decrypt)
                do_decrypt(opt.filepath, pw);

            secure_wipe(&pw[0], pw.size());
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}