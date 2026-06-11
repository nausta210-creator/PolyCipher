#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <cstring>
#include <dlfcn.h>

#include "crypto_interface.h"

enum class CryptoAction : int32_t {
    Encrypt,
    Decrypt,
    Unknown
};

void secure_vector_clear(std::vector<uint8_t>& vec) {
    volatile uint8_t* p = vec.data();
    size_t size = vec.size();
    while (size--) {
        *p++ = 0;
    }
    vec.clear();
}

void print_help(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  -a, --algorithm <name>  Specify algorithm name (e.g., rsa, vigenere)\n"
              << "  -m, --mode <mode>       Operation mode: encrypt, decrypt\n"
              << "  -k, --key <string>      Encryption/Decryption key\n"
              << "  -i, --input <path>      Path to the input file\n"
              << "  -o, --output <path>     Path to the output file\n"
              << "  -h, --help              Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_help(argv[0]);
        return 0;
    }

    std::string algo_name = "";
    std::string mode_str = "";
    std::string key_str = "";
    std::string input_path = "";
    std::string output_path = "";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if ((arg == "-a" || arg == "--algorithm") && i + 1 < argc) {
            algo_name = argv[++i];
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            mode_str = argv[++i];
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key_str = argv[++i];
        } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            input_path = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_path = argv[++i];
        }
    }

    if (algo_name.empty() || mode_str.empty() || key_str.empty() || input_path.empty() || output_path.empty()) {
        std::cerr << "Error: Missing required arguments.\n";
        print_help(argv[0]);
        return static_cast<int32_t>(CryptoStatus::InvalidParam);
    }

    CryptoAction action = CryptoAction::Unknown;
    if (mode_str == "encrypt") action = CryptoAction::Encrypt;
    if (mode_str == "decrypt") action = CryptoAction::Decrypt;

    if (action == CryptoAction::Unknown) {
        std::cerr << "Error: Unknown mode (use 'encrypt' or 'decrypt')\n";
        return static_cast<int32_t>(CryptoStatus::InvalidParam);
    }

    std::string plugin_path = "./plugins/" + algo_name + "/lib" + algo_name + ".so"; 

    void* handle = dlopen(plugin_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Error loading library: " << dlerror() << "\n";
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    using GetInfoFunc = const AlgorithmInfo*(*)();
    using GetSizeFunc = CryptoStatus(*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus(*)(ConstBuffer, ConstBuffer, MutBuffer);

    GetInfoFunc get_algorithm_info = reinterpret_cast<GetInfoFunc>(dlsym(handle, "get_algorithm_info"));
    GetSizeFunc get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    CryptoFunc encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    CryptoFunc decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    if (!get_algorithm_info || !get_output_size || !encrypt || !decrypt) {
        std::cerr << "Error: Failed to find required interface functions in plugin.\n";
        dlclose(handle);
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    const AlgorithmInfo* info = get_algorithm_info();
    std::cout << "Loaded algorithm: " << info->algorithm_name << "\n";

    std::ifstream infile(input_path, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Error: Failed to open input file.\n";
        dlclose(handle);
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    std::vector<uint8_t> input_bytes((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();

    std::vector<uint8_t> key_bytes(key_str.begin(), key_str.end());

    size_t required_output_size = 0;
    bool is_encrypt = (action == CryptoAction::Encrypt);
    
    CryptoStatus status = get_output_size(input_bytes.size(), &required_output_size, is_encrypt);
    if (status != CryptoStatus::Success) {
        std::cerr << "Error calculating output buffer size.\n";
        secure_vector_clear(input_bytes);
        secure_vector_clear(key_bytes);
        dlclose(handle);
        return static_cast<int32_t>(status);
    }

    std::vector<uint8_t> output_bytes(required_output_size);

    // Структуры-обертки для передачи через C ABI (п. 4.4.7.1 ТЗ)
    ConstBuffer in_buf { input_bytes.data(), input_bytes.size() };
    ConstBuffer key_buf { key_bytes.data(), key_bytes.size() };
    MutBuffer out_buf { output_bytes.data(), output_bytes.size() };

    if (action == CryptoAction::Encrypt) {
        status = encrypt(in_buf, key_buf, out_buf);
    } else if (action == CryptoAction::Decrypt) {
        status = decrypt(in_buf, key_buf, out_buf);
    }

    if (status != CryptoStatus::Success) {
        std::cerr << "Cryptographic operation failed with code: " << static_cast<int32_t>(status) << "\n";
        secure_vector_clear(input_bytes);
        secure_vector_clear(key_bytes);
        secure_vector_clear(output_bytes);
        dlclose(handle);
        return static_cast<int32_t>(status);
    }

    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Error: Failed to open output file for writing.\n";
        status = CryptoStatus::MemoryError;
    } else {
        outfile.write(reinterpret_cast<const char*>(output_bytes.data()), output_bytes.size());
        outfile.close();
        std::cout << "Operation successfully completed! File saved.\n";
    }

    secure_vector_clear(input_bytes);
    secure_vector_clear(key_bytes);
    secure_vector_clear(output_bytes);

    dlclose(handle);

    return static_cast<int32_t>(status);
}