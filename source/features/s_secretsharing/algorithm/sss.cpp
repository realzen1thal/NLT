#include "sss.h"
#include <sodium/sodium.h>
#include <algorithm>
#include <stdexcept>

// ─── GF(256) arithmetic ────────────────────────────────────────
// Uses the AES/Rijndael reducing polynomial x^8 + x^4 + x^3 + x + 1
// (0x11B), the standard choice for GF(256) field arithmetic — same
// field SSS implementations conventionally use.

namespace {

    uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        while (b) {
            if (b & 1) result ^= a;
            bool hi = a & 0x80;
            a <<= 1;
            if (hi) a ^= 0x1B; // reduce mod x^8+x^4+x^3+x+1
            b >>= 1;
        }
        return result;
    }

    // Precomputed log/exp tables for fast GF(256) inverse/division,
    // generator = 0x03 (a primitive element of the field).
    struct GfTables {
        uint8_t exp[512]{};
        uint8_t log[256]{};
        GfTables() {
            uint8_t x = 1;
            for (int i = 0; i < 255; ++i) {
                exp[i] = x;
                log[x] = (uint8_t)i;
                x = gf_mul(x, 0x03);
            }
            for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        }
    };
    const GfTables& tables() {
        static GfTables t;
        return t;
    }

    uint8_t gf_div(uint8_t a, uint8_t b) {
        if (a == 0) return 0;
        if (b == 0) throw std::runtime_error("SSS: division by zero in GF(256)");
        const auto& t = tables();
        int log_a = t.log[a];
        int log_b = t.log[b];
        int diff = log_a - log_b;
        if (diff < 0) diff += 255;
        return t.exp[diff];
    }

    uint8_t gf_mul_fast(uint8_t a, uint8_t b) {
        if (a == 0 || b == 0) return 0;
        const auto& t = tables();
        int sum = t.log[a] + t.log[b];
        return t.exp[sum % 255];
    }

    // Evaluates the polynomial (coeffs[0] = secret byte, coeffs[1..k-1]
    // random) at point x, in GF(256).
    uint8_t poly_eval(const std::vector<uint8_t>& coeffs, uint8_t x) {
        uint8_t result = 0;
        uint8_t x_pow = 1;
        for (uint8_t c : coeffs) {
            result ^= gf_mul_fast(c, x_pow);
            x_pow = gf_mul_fast(x_pow, x);
        }
        return result;
    }

} // namespace

// ─── Split ───────────────────────────────────────────────────────
std::vector<SssShare> sss_split(const std::vector<uint8_t>& secret, const SssConfig& cfg) {
    if (secret.empty())
        throw std::runtime_error("SSS: cannot split an empty secret");

    std::vector<SssShare> shares(cfg.n);
    for (uint8_t i = 0; i < cfg.n; ++i) {
        shares[i].index = (uint8_t)(i + 1); // 1-based; x=0 is reserved for the secret
        shares[i].data.resize(secret.size());
    }

    // Independent random polynomial per secret byte: coeffs[0] = secret
    // byte, coeffs[1..k-1] = random. Evaluate at each share's x-index.
    std::vector<uint8_t> coeffs(cfg.k);
    for (size_t byte_i = 0; byte_i < secret.size(); ++byte_i) {
        coeffs[0] = secret[byte_i];
        randombytes_buf(coeffs.data() + 1, cfg.k - 1);

        for (uint8_t s = 0; s < cfg.n; ++s) {
            shares[s].data[byte_i] = poly_eval(coeffs, shares[s].index);
        }
    }

    sodium_memzero(coeffs.data(), coeffs.size());
    return shares;
}

// ─── Combine (Lagrange interpolation at x=0) ─────────────────────
std::vector<uint8_t> sss_combine(const std::vector<SssShare>& shares) {
    if (shares.size() < 2)
        throw std::runtime_error("SSS: at least 2 shares are required to reconstruct");

    size_t secret_len = shares[0].data.size();
    for (const auto& s : shares)
        if (s.data.size() != secret_len)
            throw std::runtime_error("SSS: shares have mismatched lengths — do they belong together?");

    // Reject duplicate share indices — Lagrange interpolation requires
    // distinct x-coordinates, and silently ignoring a dup could make
    // reconstruction look like it "worked" while actually using fewer
    // distinct points than the caller thinks.
    std::vector<uint8_t> seen;
    for (const auto& s : shares) {
        if (std::find(seen.begin(), seen.end(), s.index) != seen.end())
            throw std::runtime_error("SSS: duplicate share index detected — shares must be distinct");
        seen.push_back(s.index);
    }

    std::vector<uint8_t> secret(secret_len, 0);

    for (size_t byte_i = 0; byte_i < secret_len; ++byte_i) {
        uint8_t result = 0;
        for (size_t i = 0; i < shares.size(); ++i) {
            uint8_t xi = shares[i].index;
            uint8_t yi = shares[i].data[byte_i];

            // Lagrange basis polynomial L_i(0) = product over j!=i of
            // (0 - x_j) / (x_i - x_j), all in GF(256) (where subtraction
            // == addition == XOR).
            uint8_t num = 1, den = 1;
            for (size_t j = 0; j < shares.size(); ++j) {
                if (j == i) continue;
                uint8_t xj = shares[j].index;
                num = gf_mul_fast(num, xj);          // (0 - x_j) == x_j in GF(2^n)
                den = gf_mul_fast(den, xi ^ xj);      // (x_i - x_j) == x_i ^ x_j
            }
            uint8_t li0 = gf_div(num, den);
            result ^= gf_mul_fast(yi, li0);
        }
        secret[byte_i] = result;
    }

    return secret;
}