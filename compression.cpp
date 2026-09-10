#include "compression.h"
#include <stdexcept>

// ─── Compressor ───────────────────────────────────────────────
Compressor::Compressor(size_t chunk_size) {
    if (deflateInit(&zs_, Z_BEST_COMPRESSION) != Z_OK)
        throw std::runtime_error("deflateInit");
    active_ = true;
    cbuf_.resize(chunk_size + (chunk_size / 10) + 256);
}

Compressor::~Compressor() {
    if (active_) deflateEnd(&zs_);
}

void Compressor::compress(const unsigned char* in, size_t in_len, bool last,
    std::vector<unsigned char>& out) {
    zs_.next_in = const_cast<Bytef*>(in);
    zs_.avail_in = (uInt)in_len;
    out.clear();

    int flush = last ? Z_FINISH : Z_SYNC_FLUSH;
    do {
        zs_.next_out = cbuf_.data();
        zs_.avail_out = (uInt)cbuf_.size();
        int r = deflate(&zs_, flush);
        if (r == Z_STREAM_ERROR) throw std::runtime_error("deflate err");
        size_t produced = cbuf_.size() - zs_.avail_out;
        out.insert(out.end(), cbuf_.data(), cbuf_.data() + produced);
    } while (zs_.avail_out == 0);
}

// ─── Decompressor ─────────────────────────────────────────────
Decompressor::Decompressor(size_t chunk_size) {
    if (inflateInit(&zs_) != Z_OK)
        throw std::runtime_error("inflateInit");
    active_ = true;
    dbuf_.resize(chunk_size * 2);
}

Decompressor::~Decompressor() {
    if (active_) inflateEnd(&zs_);
}

void Decompressor::decompress(const unsigned char* in, size_t in_len,
    std::vector<unsigned char>& out) {
    zs_.next_in = const_cast<Bytef*>(in);
    zs_.avail_in = (uInt)in_len;
    out.clear();

    do {
        zs_.next_out = dbuf_.data();
        zs_.avail_out = (uInt)dbuf_.size();
        int r = inflate(&zs_, Z_SYNC_FLUSH);
        if (r == Z_STREAM_ERROR || r == Z_DATA_ERROR)
            throw std::runtime_error("Decompress error");
        size_t produced = dbuf_.size() - zs_.avail_out;
        out.insert(out.end(), dbuf_.data(), dbuf_.data() + produced);
    } while (zs_.avail_out == 0);
}