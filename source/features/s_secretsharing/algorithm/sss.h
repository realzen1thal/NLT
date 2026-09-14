#pragma once
#include <cstdint>
#include <vector>

// ─── Shamir's Secret Sharing — core math only (GF(256)) ─────────
//
// Splits a secret (arbitrary byte string, e.g. a randomly generated
// password) into `n` shares such that any `k` of them can reconstruct
// it, but any (k-1) reveal nothing about the secret at all.
//
// Each byte of the secret is treated as a separate polynomial's
// constant term over GF(256); share value at share-index `x` is the
// polynomial evaluated at `x`. Reconstruction uses Lagrange
// interpolation at x=0, per byte.
//
// This file is ONLY the algorithm. It has no opinion on what N/K
// values are acceptable, no file format, no CLI parsing — all of
// that (including "--sss X-Y" validation, refusing 1-1, etc.) lives
// in sss_shares.h/.cpp, which calls into this module.

struct SssConfig {
    uint8_t n; // total number of shares
    uint8_t k; // threshold required to reconstruct
};

// A single share: its 1-based index (1..n, never 0 — x=0 is reserved
// for the secret itself) and its share bytes (same length as the
// original secret).
struct SssShare {
    uint8_t index;
    std::vector<uint8_t> data;
};

// Splits `secret` into `cfg.n` shares, any `cfg.k` of which reconstruct it.
// Assumes cfg has already been validated by the caller (n>=2, k>=2,
// k<=n, n<=255) — this function does not re-validate policy, only the
// structural precondition that `secret` is non-empty.
std::vector<SssShare> sss_split(const std::vector<uint8_t>& secret, const SssConfig& cfg);

// Reconstructs the original secret from >= 2 shares. Shares can be
// passed in any order; duplicate indices are rejected since Lagrange
// interpolation requires distinct x-coordinates. Does not know or
// enforce any particular threshold K — the caller is responsible for
// having gathered enough shares before calling this.
std::vector<uint8_t> sss_combine(const std::vector<SssShare>& shares);