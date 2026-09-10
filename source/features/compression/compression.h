#pragma once
#include <zlib/zlib.h>
#include <vector>
#include <cstdint>

// Thin RAII-ish wrapper around zlib streaming (de)compression, sized
// to the same adaptive chunk used by the encrypt/decrypt pipeline.

class Compressor {
public:
    // chunk_size should match the pipeline's adaptive buffer size.
    explicit Compressor(size_t chunk_size);
    ~Compressor();

    Compressor(const Compressor&) = delete;
    Compressor& operator=(const Compressor&) = delete;

    // Compresses `in` (len `in_len`). If `last` is true, finalizes the
    // deflate stream (Z_FINISH); otherwise flushes with Z_SYNC_FLUSH so
    // output can be safely written incrementally. Appends produced bytes
    // to `out` (out is cleared first).
    void compress(const unsigned char* in, size_t in_len, bool last,
        std::vector<unsigned char>& out);

private:
    z_stream zs_{};
    std::vector<unsigned char> cbuf_;
    bool active_ = false;
};

class Decompressor {
public:
    explicit Decompressor(size_t chunk_size);
    ~Decompressor();

    Decompressor(const Decompressor&) = delete;
    Decompressor& operator=(const Decompressor&) = delete;

    // Inflates `in` (len `in_len`) fully (loops until avail_out > 0),
    // appending produced bytes to `out` (out is cleared first).
    void decompress(const unsigned char* in, size_t in_len,
        std::vector<unsigned char>& out);

private:
    z_stream zs_{};
    std::vector<unsigned char> dbuf_;
    bool active_ = false;
};