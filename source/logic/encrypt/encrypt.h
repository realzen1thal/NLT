#pragma once
#include <string>

// Streams `path` through Argon2id-derived XChaCha20-Poly1305 secretstream
// encryption (optionally zlib-compressed first), writing the result to a
// temp file and atomically replacing the original. Adaptive chunk sizing
// based on file size (see settings.h).
void do_encrypt(const std::string& path, const std::string& pw, bool compress);