#include "encrypt.h"
#include "../../common.h"
#include "../../settings/settings.h"
#include "../../features/compression/compression.h"

#include <sodium/sodium.h>
#include <fstream>
#include <array>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <iostream>

namespace fs = std::filesystem;

void do_encrypt(const std::string& path, const std::string& pw, bool compress) {
    std::ifstream fin(path, std::ios::binary | std::ios::ate);
    if (!fin) throw std::runtime_error("Cannot open: " + path);
    uint64_t orig = fin.tellg();
    fin.seekg(0);

    // Adaptive buffer sizing
    auto buf_cfg = get_optimal_buffer(orig);
    size_t CHUNK = buf_cfg.chunk_size;
    std::cout << "  Buffer: " << buf_cfg.label << " (adaptive)\n";

    SecureBuf salt(SALT_LEN); randombytes_buf(salt.p(), SALT_LEN);
    SecureBuf key(KEY_LEN);
    if (crypto_pwhash(key.p(), KEY_LEN, pw.data(), pw.size(), salt.p(),
        crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
        throw std::runtime_error("KDF failed");

    unsigned char sshdr[SS_HDR_LEN];
    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_push(&st, sshdr, key.p());

    std::string tmp = path + ".tmp";
    std::ofstream fout(tmp, std::ios::binary);
    if (!fout) throw std::runtime_error("Cannot create temp");

    uint8_t fl = compress ? FLAG_COMPRESSED : 0;
    fout.write((char*)salt.p(), SALT_LEN);
    fout.write((char*)sshdr, SS_HDR_LEN);
    fout.write((char*)&fl, 1);
    fout.write((char*)&orig, sizeof(uint64_t));

    std::unique_ptr<Compressor> comp;
    if (compress) comp = std::make_unique<Compressor>(CHUNK);

    // Double buffer sized to adaptive chunk
    std::array<std::vector<unsigned char>, 2> db;
    db[0].resize(CHUNK);
    db[1].resize(CHUNK);
    int ai = 0;
    uint64_t rd = 0;

    Progress pb(compress ? "Compress+Encrypt" : "Encrypting", orig);

    while (rd < orig) {
        size_t want = (std::min)((uint64_t)CHUNK, orig - rd);
        fin.read((char*)db[ai].data(), want);
        size_t got = fin.gcount();
        rd += got;
        bool last = (rd >= orig);

        const unsigned char* pp = db[ai].data();
        size_t pl = got;
        std::vector<unsigned char> cc;

        if (comp) {
            comp->compress(pp, got, last, cc);
            pp = cc.data();
            pl = cc.size();
        }

        std::vector<unsigned char> ct(pl + ABYTES);
        unsigned long long ctl = 0;
        unsigned char tag = last
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        crypto_secretstream_xchacha20poly1305_push(
            &st, ct.data(), &ctl, pp, pl, nullptr, 0, tag);

        write_u32(fout, (uint32_t)ctl);
        fout.write((char*)ct.data(), ctl);

        ai ^= 1;
        pb.upd(rd);
    }

    fin.close(); fout.close(); pb.done();
    fs::remove(path); fs::rename(tmp, path);

    auto final_sz = fs::file_size(path);
    std::cout << "[+] Encrypted: " << path
        << " (" << orig << " -> " << final_sz << " bytes)\n";
}