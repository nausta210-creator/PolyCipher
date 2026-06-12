#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <iterator>
#include <random>
#include <dlfcn.h>
#include "crypto_interface.h"

enum class CryptoAction : int32_t {
    Encrypt,
    Decrypt,
    GenKey,
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

void print_help() {
    std::cout << "Usage: ./PolyCipher [options]\n"
              << "Options:\n"
              << "  -a, --algorithm <name>  Specify algorithm name (e.g., rsa, vigenere)\n"
              << "  -m, --mode <mode>       Operation mode: encrypt, decrypt, genkey\n"
              << "  -k, --key <string>      Encryption/Decryption key (or path to key file)\n"
              << "  -i, --input <path>      Path to the input file (Default: stdin)\n"
              << "  -o, --output <path>     Path to the output file (Default: stdout)\n"
              << "  -h, --help              Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_help();
        return 0;
    }

    std::string algo_name;
    std::string mode_str;
    std::string key_param;
    std::string input_path;
    std::string output_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-h" || arg == "--help")) {
            print_help();
            return 0;
        } else if ((arg == "-a" || arg == "--algorithm") && i + 1 < argc) {
            algo_name = argv[++i];
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            mode_str = argv[++i];
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key_param = argv[++i];
        } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            input_path = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_path = argv[++i];
        }
    }

    CryptoAction action = CryptoAction::Unknown;
    if (mode_str == "encrypt") action = CryptoAction::Encrypt;
    else if (mode_str == "decrypt") action = CryptoAction::Decrypt;
    else if (mode_str == "genkey")  action = CryptoAction::GenKey;

    if (algo_name.empty() || action == CryptoAction::Unknown) {
        std::cerr << "Error: Invalid or missing algorithm/mode.\n";
        print_help();
        return 1;
    }

    if (action == CryptoAction::GenKey) {
        std::vector<uint8_t> generated_key;
        
        if (algo_name == "vigenere" || algo_name == "rc4" || algo_name == "rsa" || algo_name == "elgamal") {
            std::string lib_path = "./plugins/" + algo_name + "/lib" + algo_name + ".so";
            void* plugin_handle = dlopen(lib_path.c_str(), RTLD_LAZY);
            
            if (!plugin_handle) {
                std::cerr << "Error: Cannot load " << algo_name << " plugin for key generation. (" << dlerror() << ")\n";
                return 1;
            }

            uint64_t param1 = 0, param2 = 0;

            if (algo_name == "rsa") {
                std::cout << "Введите первое простое число (p): "; std::cin >> param1;
                std::cout << "Введите второе простое число (q): "; std::cin >> param2;
            } else if (algo_name == "elgamal") {
                std::cout << "Введите простое число (p): "; std::cin >> param1;
                std::cout << "Введите основание/генератор (g): "; std::cin >> param2;
            }

            std::string func_name = "generate_" + algo_name + "_keys";
            
            using GenKeysFunc = CryptoStatus (*)(uint64_t, uint64_t, char*, size_t, size_t*);
            auto generate_keys = reinterpret_cast<GenKeysFunc>(dlsym(plugin_handle, func_name.c_str()));

            if (!generate_keys) {
                std::cerr << "Error: Plugin missing '" << func_name << "' function.\n";
                dlclose(plugin_handle);
                return 1;
            }

            char buffer[512] = {0};
            size_t bytes_written = 0;

            CryptoStatus status = generate_keys(param1, param2, buffer, sizeof(buffer), &bytes_written);
            
            if (status == CryptoStatus::InvalidParam && algo_name == "rsa") {
                std::cerr << "Error: Invalid parameters. Both p and q must be prime numbers!\n";
                dlclose(plugin_handle);
                return 1;
            } else if (status != CryptoStatus::Success) {
                std::cerr << "Error: Key generation failed inside " << algo_name << " plugin.\n";
                dlclose(plugin_handle);
                return 1;
            }

            generated_key.assign(buffer, buffer + bytes_written);
            dlclose(plugin_handle);

        } else {
            std::cerr << "Error: Unknown algorithm for key generation.\n";
            return 1;
        }

        if (!output_path.empty()) {
            std::ofstream key_file(output_path, std::ios::binary);
            if (!key_file.is_open()) {
                std::cerr << "Error: Cannot open file for writing key.\n";
                secure_vector_clear(generated_key);
                return 1;
            }
            key_file.write(reinterpret_cast<const char*>(generated_key.data()), generated_key.size());
            key_file.close();
        } else {
            std::cout.write(reinterpret_cast<const char*>(generated_key.data()), generated_key.size());
            std::cout << "\n";
        }
        secure_vector_clear(generated_key);
        return 0; 
    }


    std::vector<uint8_t> key_data;
    if (!key_param.empty()) {
        std::ifstream key_file(key_param, std::ios::binary); 
        if (key_file.is_open()) {
            key_file >> std::noskipws;
            key_data.assign((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());
            key_file.close();
        } else {
            key_data.assign(key_param.begin(), key_param.end());
        }
    } else {
        std::cerr << "Enter cryptographic key: ";
        std::string temp_key;
        std::getline(std::cin, temp_key);
        key_data.assign(temp_key.begin(), temp_key.end());
    }

    if (key_data.empty()) {
        std::cerr << "Error: Key cannot be empty.\n";
        return 1;
    }

    std::vector<uint8_t> input_data;
    if (!input_path.empty()) {
        std::ifstream infile(input_path, std::ios::binary);
        if (!infile.is_open()) {
            std::cerr << "Error: Cannot open input file " << input_path << "\n";
            secure_vector_clear(key_data);
            return 1;
        }
        input_data.assign((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
        infile.close();
    } else {
        std::noskipws(std::cin);
        input_data.assign(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>());
    }

    if (input_data.empty()) {
        std::cerr << "Error: No input data provided.\n";
        secure_vector_clear(key_data);
        return 1;
    }

    std::string lib_path = "./plugins/" + algo_name + "/lib" + algo_name + ".so";
    void* handle = dlopen(lib_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Error: Cannot load plugin " << lib_path << " (" << dlerror() << ")\n";
        secure_vector_clear(key_data);
        secure_vector_clear(input_data);
        return 1;
    }

    using GetInfoFunc = const AlgorithmInfo* (*)();
    using GetSizeFunc = CryptoStatus (*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus (*)(ConstBuffer, ConstBuffer, MutBuffer);

    auto get_algorithm_info = reinterpret_cast<GetInfoFunc>(dlsym(handle, "get_algorithm_info"));
    auto get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    auto encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    auto decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    if (!get_algorithm_info || !get_output_size || !encrypt || !decrypt) {
        std::cerr << "Error: Plugin missing required exported functions C ABI.\n";
        secure_vector_clear(key_data);
        secure_vector_clear(input_data);
        dlclose(handle);
        return 1;
    }

    const AlgorithmInfo* info = get_algorithm_info();

    if (info && info->key_size > 0 && key_data.size() != info->key_size) {
        std::cerr << "Error: Invalid key size for algorithm " << info->algorithm_name 
                  << ". Expected " << info->key_size << " bytes, but got " 
                  << key_data.size() << " bytes.\n";
        secure_vector_clear(key_data);
        secure_vector_clear(input_data);
        dlclose(handle);
        return 1;
    }

    ConstBuffer src_buf{ input_data.data(), input_data.size() };
    ConstBuffer k_buf{ key_data.data(), key_data.size() };

    size_t out_size = 0;
    CryptoStatus status = get_output_size(input_data.size(), &out_size, action == CryptoAction::Encrypt);
    if (status != CryptoStatus::Success) {
        std::cerr << "Error: Plugin get_output_size failed with code " << static_cast<int>(status) << "\n";
        secure_vector_clear(key_data);
        secure_vector_clear(input_data);
        dlclose(handle);
        return 1;
    }

    std::vector<uint8_t> output_data(out_size);
    MutBuffer dst_buf{ output_data.data(), output_data.size() };

    if (action == CryptoAction::Encrypt) {
        status = encrypt(src_buf, k_buf, dst_buf);
    } else {
        status = decrypt(src_buf, k_buf, dst_buf);
    }

    if (status != CryptoStatus::Success) {
        std::cerr << "Error: Cryptographic operation failed with code " << static_cast<int>(status) << "\n";
        secure_vector_clear(key_data);
        secure_vector_clear(input_data);
        secure_vector_clear(output_data);
        dlclose(handle);
        return 1;
    }

    if (!output_path.empty()) {
        std::ofstream outfile(output_path, std::ios::binary);
        if (!outfile.is_open()) {
            std::cerr << "Error: Cannot open output file " << output_path << "\n";
        } else {
            outfile.write(reinterpret_cast<const char*>(output_data.data()), dst_buf.size);
            outfile.close();
        }
    } else {
        std::cout.write(reinterpret_cast<const char*>(output_data.data()), dst_buf.size);
    }

    secure_vector_clear(key_data);
    secure_vector_clear(input_data);
    secure_vector_clear(output_data);
    dlclose(handle);
    return 0;
}