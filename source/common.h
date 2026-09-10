#pragma once
#define NOMINMAX

#include <sodium/sodium.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// ─── Constants ───────────────────────────────────────────────
constexpr size_t SALT_LEN = crypto_pwhash_SALTBYTES;
constexpr size_t KEY_LEN = crypto_secretstream_xchacha20poly1305_KEYBYTES;
constexpr size_t SS_HDR_LEN = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
constexpr size_t ABYTES = crypto_secretstream_xchacha20poly1305_ABYTES;
constexpr uint8_t FLAG_COMPRESSED = 0x01;

// File header: salt(16) + ss_header(24) + flags(1) + orig_size(8) = 49
constexpr size_t FILE_HDR = SALT_LEN + SS_HDR_LEN + 1 + sizeof(uint64_t);

// ─── Secure Memory ──────────────────────────────────────────
inline void secure_wipe(void* p, size_t n) { sodium_memzero(p, n); }

class SecureBuf {
    std::vector<unsigned char> d_;
public:
    explicit SecureBuf(size_t n = 0) : d_(n, 0) {}
    ~SecureBuf() { secure_wipe(d_.data(), d_.size()); }
    unsigned char* p() { return d_.data(); }
    const unsigned char* p() const { return d_.data(); }
    size_t sz() const { return d_.size(); }
    void rsz(size_t n) { d_.resize(n, 0); }
    SecureBuf(const SecureBuf&) = delete;
    SecureBuf& operator=(const SecureBuf&) = delete;
};

// ─── Progress Bar ───────────────────────────────────────────
class Progress {
    std::string l_;
    uint64_t t_, c_ = 0;
    std::chrono::steady_clock::time_point s_;
public:
    Progress(std::string l, uint64_t t)
        : l_(std::move(l)), t_(t), s_(std::chrono::steady_clock::now()) {
    }
    void upd(uint64_t v) { c_ = v; draw(); }
    void done() { c_ = t_; draw(); std::cout << "\n"; }
private:
    void draw() {
        auto e = std::chrono::steady_clock::now() - s_;
        double sec = std::chrono::duration<double>(e).count();
        double pct = t_ > 0 ? (double)c_ / t_ * 100.0 : 100.0;
        double r = sec > 0.001 ? c_ / sec : 0;
        double eta = (r > 0 && c_ < t_) ? (t_ - c_) / r : 0;
        int bw = 30, f = (int)(pct / 100.0 * bw);
        std::cout << "\r" << l_ << " ["
            << std::string(f, '#') << std::string(bw - f, '-')
            << "] " << std::fixed << std::setprecision(1) << pct << "% | Duration: "
            << std::setprecision(1) << sec << "s";
        if (c_ < t_ && eta > 0)
            std::cout << " | ETA: " << std::setprecision(1) << eta << "s";
        std::flush(std::cout);
    }
};

// ─── Password Input ─────────────────────────────────────────

// True if stdin is an interactive terminal (no pipe/redirect feeding it).
inline bool stdin_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

// Masked interactive prompt (used only when stdin is a real terminal).
inline std::string prompt_password_masked() {
    std::cout << "Password: "; std::flush(std::cout);
    std::string pw;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE); DWORD m; GetConsoleMode(h, &m);
    SetConsoleMode(h, m & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
    char c; DWORD n;
    while (ReadFile(h, &c, 1, &n, nullptr) && n == 1) {
        if (c == '\r' || c == '\n') break;
        if (c == '\b' || c == 127) { if (!pw.empty()) pw.pop_back(); }
        else pw += c;
    }
    SetConsoleMode(h, m); std::cout << "\n";
#else
    termios o, n; tcgetattr(STDIN_FILENO, &o);
    n = o; n.c_lflag &= ~(ECHO | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &n);
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &o); std::cout << "\n";
#endif
    return pw;
}

// Reads a single line from stdin as-is (used when stdin is piped/redirected —
// e.g. `cat secret.txt | tool encrypt file` or `tool encrypt file <<< "$PW"`).
inline std::string read_password_from_stdin() {
    std::string pw;
    std::getline(std::cin, pw);
    return pw;
}

// Standard password resolution: no flag needed. If stdin is piped/redirected,
// read the password from it silently (script/automation friendly, and keeps
// the password out of argv/ps/shell history). If stdin is a real terminal,
// fall back to the masked interactive prompt.
inline std::string resolve_password() {
    if (stdin_is_tty()) return prompt_password_masked();
    return read_password_from_stdin();
}

// ─── LE u32 Helpers ─────────────────────────────────────────
inline void write_u32(std::ostream& o, uint32_t v) {
    unsigned char b[4]; memcpy(b, &v, 4); o.write((char*)b, 4);
}
inline uint32_t read_u32(std::istream& i) {
    unsigned char b[4]; i.read((char*)b, 4); uint32_t v; memcpy(&v, b, 4); return v;
}