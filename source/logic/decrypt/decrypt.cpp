#include "decrypt.h"
#include "../../common.h"
#include "../../settings/settings.h"
#include "../../features/compression/compression.h"

#include <sodium/sodium.h>
#include <fstream>
#include <vector>
#include <memory>
#include <filesystem>
#include <stdexcept>
#include <iostream>

namespace fs = std::filesystem;

void do_decrypt(const std::string& path, const std::string& pw) {
    std::ifstream fin(path, std::ios::binary);
    if (!fin) throw std::runtime_error("Cannot open: " + path);

    // Get file size for adaptive buffering
    fin.seekg(0, std::ios::end);
    uint64_t enc_file_size = fin.tellg();
    fin.seekg(0);

    auto buf_cfg = get_optimal_buffer(enc_file_size);
    size_t CHUNK = buf_cfg.chunk_size;
    std::cout << "  Buffer: " << buf_cfg.label << " (adaptive)\n";

    SecureBuf salt(SALT_LEN); fin.read((char*)salt.p(), SALT_LEN);
    unsigned char sshdr[SS_HDR_LEN]; fin.read((char*)sshdr, SS_HDR_LEN);
    uint8_t fl; fin.read((char*)&fl, 1);
    uint64_t orig; fin.read((char*)&orig, sizeof(uint64_t));
    if (!fin) throw std::runtime_error("Bad header");

    bool was_comp = (fl & FLAG_COMPRESSED) != 0;

    SecureBuf key(KEY_LEN);
    if (crypto_pwhash(key.p(), KEY_LEN, pw.data(), pw.size(), salt.p(),
        crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
        throw std::runtime_error("KDF failed");

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, sshdr, key.p()) != 0)
        throw std::runtime_error("Decryption FAILED — wrong password or tampered");

    std::unique_ptr<Decompressor> decomp;
    if (was_comp) decomp = std::make_unique<Decompressor>(CHUNK);

    std::string tmp = path + ".tmp";
    std::ofstream fout(tmp, std::ios::binary);
    if (!fout) throw std::runtime_error("Cannot create temp");

    uint64_t enc_data = enc_file_size - FILE_HDR;
    Progress pb(was_comp ? "Decrypt+Decompress" : "Decrypting", enc_data);
    uint64_t consumed = 0;

    SecureBuf ct_buf(CHUNK + ABYTES + 256);
    SecureBuf pt_buf(CHUNK);

    while (!fin.eof()) {
        if (fin.peek() == EOF) break;
        uint32_t ctl = read_u32(fin);
        if (!fin || ctl == 0) break;
        if (ctl > ct_buf.sz()) ct_buf.rsz(ctl);
        fin.read((char*)ct_buf.p(), ctl);
        if (!fin) throw std::runtime_error("Truncated ciphertext");
        consumed += 4 + ctl;

        unsigned long long ptl = 0; unsigned char tag;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, pt_buf.p(), &ptl, &tag,
            ct_buf.p(), ctl, nullptr, 0) != 0)
            throw std::runtime_error("Chunk auth failed — tampered");

        const unsigned char* op = pt_buf.p();
        size_t ol = ptl;
        std::vector<unsigned char> dc;

        if (decomp) {
            decomp->decompress(op, ol, dc);
            op = dc.data();
            ol = dc.size();
        }

        fout.write((char*)op, ol);
        pb.upd(consumed);
    }

    fin.close(); fout.close(); pb.done();
    fs::remove(path); fs::rename(tmp, path);

    auto final_sz = fs::file_size(path);
    std::cout << "[+] Decrypted: " << path
        << " (" << enc_file_size << " -> " << final_sz << " bytes)\n";
}