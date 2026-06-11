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
        std::string generated_key_str;
        
        if (algo_name == "vigenere") {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distr('a', 'z');
            for (int j = 0; j < 16; ++j) {
                generated_key_str += static_cast<char>(distr(gen));
            }
        } else if (algo_name == "rsa") {
            generated_key_str = "Public: 7,3233\nPrivate: 1783,3233";
        } else {
            std::cerr << "Error: Unknown algorithm for key generation.\n";
            return 1;
        }

        if (!output_path.empty()) {
            std::ofstream key_file(output_path);
            if (!key_file.is_open()) {
                std::cerr << "Error: Cannot open file for writing key.\n";
                return 1;
            }
            key_file << generated_key_str;
            key_file.close();
        } else {
            std::cout << generated_key_str << "\n";
        }
        return 0; 
    }

    std::string key_str = key_param;
    if (!key_param.empty()) {
        std::ifstream key_file(key_param);
        if (key_file.is_open()) {
            std::string file_content((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());
            if (!file_content.empty()) {
                key_str = file_content;
            }
            key_file.close();
        }
    } else {
        std::cerr << "Enter cryptographic key: ";
        std::getline(std::cin, key_str);
    }

    if (key_str.empty()) {
        std::cerr << "Error: Key cannot be empty.\n";
        return 1;
    }

    std::vector<uint8_t> input_data;
    if (!input_path.empty()) {
        std::ifstream infile(input_path, std::ios::binary);
        if (!infile.is_open()) {
            std::cerr << "Error: Cannot open input file " << input_path << "\n";
            return 1;
        }
        input_data.assign((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
        infile.close();
    } else {
        std::noskipws(std::cin);
        input_data.assign(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>());
    }

    if (input_data.empty() && action != CryptoAction::GenKey) {
        std::cerr << "Error: No input data provided.\n";
        return 1;
    }

    std::string lib_path = "./lib" + algo_name + ".so";
    void* handle = dlopen(lib_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Error: Cannot load plugin " << lib_path << " (" << dlerror() << ")\n";
        return 1;
    }

    auto get_algorithm_info = reinterpret_cast<get_algorithm_info_t>(dlsym(handle, "get_algorithm_info"));
    auto get_output_size = reinterpret_cast<get_output_size_t>(dlsym(handle, "get_output_size"));
    auto encrypt = reinterpret_cast<encrypt_t>(dlsym(handle, "encrypt"));
    auto decrypt = reinterpret_cast<decrypt_t>(dlsym(handle, "decrypt"));

    if (!get_algorithm_info || !get_output_size || !encrypt || !decrypt) {
        std::cerr << "Error: Plugin missing required exported functions C ABI.\n";
        dlclose(handle);
        return 1;
    }

    AlgorithmInfo info;
    get_algorithm_info(&info);

    ConstBuffer src_buf{ input_data.data(), input_data.size() };
    ConstBuffer k_buf{ reinterpret_cast<const uint8_t*>(key_str.data()), key_str.size() };

    size_t out_size = 0;
    CryptoStatus status = get_output_size(action == CryptoAction::Encrypt, &src_buf, &k_buf, &out_size);
    if (status != CryptoStatus::Success) {
        std::cerr << "Error: Plugin get_output_size failed with code " << static_cast<int>(status) << "\n";
        dlclose(handle);
        return 1;
    }

    std::vector<uint8_t> output_data(out_size);
    MutBuffer dst_buf{ output_data.data(), output_data.size() };

    if (action == CryptoAction::Encrypt) {
        status = encrypt(&src_buf, &k_buf, &dst_buf);
    } else {
        status = decrypt(&src_buf, &k_buf, &dst_buf);
    }

    if (status != CryptoStatus::Success) {
        std::cerr << "Error: Cryptographic operation failed with code " << static_cast<int>(status) << "\n";
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

    secure_vector_clear(input_data);
    secure_vector_clear(output_data);
    dlclose(handle);
    return 0;
}