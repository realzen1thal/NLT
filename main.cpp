#include "common.h"
#include "settings.h"
#include "../encrypt.h"
#include "../decrypt.h"

#include <sodium/sodium.h>
#include <iostream>

int main(int argc, char** argv) {
    if (sodium_init() < 0) { std::cerr << "sodium fail\n"; return 1; }

    CliOptions opt;
    if (!parse_cli(argc, argv, opt)) {
        print_usage(argv[0]);
        return 1;
    }

    std::string pw = resolve_password();
    if (pw.empty()) { std::cerr << "Empty password\n"; return 1; }

    try {
        if (opt.command == Command::Encrypt)
            do_encrypt(opt.filepath, pw, !opt.no_compression);
        else if (opt.command == Command::Decrypt)
            do_decrypt(opt.filepath, pw);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        secure_wipe(&pw[0], pw.size());
        return 1;
    }

    secure_wipe(&pw[0], pw.size());
    return 0;
}