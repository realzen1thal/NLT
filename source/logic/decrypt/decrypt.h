#pragma once
#include <string>

// Reverses do_encrypt: reads salt/secretstream header from `path`,
// derives the key from `pw`, verifies + decrypts each chunk (and
// decompresses if the file was flagged compressed), writing the
// result to a temp file and atomically replacing the original.
void do_decrypt(const std::string& path, const std::string& pw);