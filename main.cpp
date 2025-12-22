#include "aes_encryption_system.h"
#include "aes_mode.h"
#include <iostream>
#include <limits>

#define LOG(x) std::cout << x << std::endl;

enum class Command {
    LOAD_KEY,
    SET_MODE,
    LOAD_DATA,
    START,
    READ_RESULT,
    ROUNDTRIP,
    INVALID
};

Command parse_command(const std::string& input) {
    if (input == "loadkey") return Command::LOAD_KEY;
    if (input == "encrypt") return Command::SET_MODE;
    if (input == "decrypt") return Command::SET_MODE;
    if (input == "loaddata") return Command::LOAD_DATA;
    if (input == "start") return Command::START;
    if (input == "read") return Command::READ_RESULT;
    if (input == "roundtrip") return Command::ROUNDTRIP;
    return Command::INVALID;
}

int main() {
    LOG("=== AES Test ===");
    AESEncryptionSystem aes;
    std::string input;

    uint8_t dummy_key[16] = {
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t out[16] = {0 };

    std::cout << "AES Controller Terminal\n";

    while (true) {
        std::cout << "> ";
        std::cin >> input;

        Command cmd = parse_command(input);

        switch (cmd) {
        case Command::LOAD_KEY:
            aes.load_key(dummy_key);
            break;

        case Command::SET_MODE:
            if (input == "encrypt")
                aes.set_mode(AESMode::ENCRYPT);
            else
                aes.set_mode(AESMode::DECRYPT);
            break;

        case Command::LOAD_DATA: {
            // Flush the rest of the current line
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Enter text (max16 bytes, will truncate/zero-pad): ";
            std::string text;
            std::getline(std::cin, text);

            uint8_t buf[16] = {0};
            size_t n = text.size();
            if (n >16) {
                std::cout << "Input longer than16 bytes, truncating to first16.\n";
                n =16;
            }
            for (size_t i =0; i < n; ++i) buf[i] = static_cast<uint8_t>(text[i]);

            aes.load_data(buf);
            break;
        }
        case Command::START:
            aes.start();
            break;

        case Command::READ_RESULT:
            aes.read_result(out);
            std::cout << "Read result:";
            for (auto b : out) std::cout << " " << std::hex << (int)b;
            std::cout << std::dec << std::endl;
            break;

        case Command::ROUNDTRIP: {
            // Flush rest of line and read input text
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Enter text (max16 bytes, will truncate/zero-pad): ";
            std::string text;
            std::getline(std::cin, text);
            size_t n = text.size();
            if (n >16) {
                std::cout << "Input longer than16 bytes, truncating to first16.\n";
                n =16;
            }
            uint8_t plain[16] = {0};
            for (size_t i =0; i < n; ++i) plain[i] = static_cast<uint8_t>(text[i]);

            // Load key, set encrypt, encrypt
            aes.load_key(dummy_key);
            aes.set_mode(AESMode::ENCRYPT);
            aes.load_data(plain);
            aes.start();
            uint8_t cipher[16] = {0};
            aes.read_result(cipher);
            std::cout << "Cipher (hex):";
            for (auto b : cipher) std::cout << " " << std::hex << (int)b;
            std::cout << std::dec << std::endl;

            // Now decrypt back
            aes.set_mode(AESMode::DECRYPT);
            aes.load_data(cipher);
            aes.start();
            uint8_t roundtrip[16] = {0};
            aes.read_result(roundtrip);

            std::string recovered(roundtrip, roundtrip + n);
            std::cout << "Recovered text: " << recovered << std::endl;
            break;
        }

        default:
            std::cout << "Invalid command.\n";
        }
    }
}
