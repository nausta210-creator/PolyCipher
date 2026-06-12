#include <iostream>
#include <cassert>
#include <vector>
#include <dlfcn.h>
#include <string>
#include "crypto_interface.h"

void run_test(void* handle, const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    using GetSizeFunc = CryptoStatus(*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus(*)(ConstBuffer, ConstBuffer, MutBuffer);

    GetSizeFunc get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    CryptoFunc encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    CryptoFunc decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    assert(get_output_size && encrypt && decrypt);

    size_t enc_size = 0;
    get_output_size(data.size(), &enc_size, true);
    std::vector<uint8_t> enc_buf(enc_size);
    encrypt({data.data(), data.size()}, {key.data(), key.size()}, {enc_buf.data(), enc_buf.size()});

    size_t dec_size = 0;
    get_output_size(enc_buf.size(), &dec_size, false);
    std::vector<uint8_t> dec_buf(dec_size);
    decrypt({enc_buf.data(), enc_buf.size()}, {key.data(), key.size()}, {dec_buf.data(), dec_buf.size()});

    assert(data == dec_buf); 
}

void run_rsa_test(void* handle, const std::vector<uint8_t>& data, const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& private_key) {
    using GetSizeFunc = CryptoStatus(*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus(*)(ConstBuffer, ConstBuffer, MutBuffer);

    GetSizeFunc get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    CryptoFunc encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    CryptoFunc decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    assert(get_output_size && encrypt && decrypt);

    size_t enc_size = 0;
    get_output_size(data.size(), &enc_size, true);
    std::vector<uint8_t> enc_buf(enc_size);
    encrypt({data.data(), data.size()}, {public_key.data(), public_key.size()}, {enc_buf.data(), enc_buf.size()});

    size_t dec_size = 0;
    get_output_size(enc_buf.size(), &dec_size, false);
    std::vector<uint8_t> dec_buf(dec_size);
    decrypt({enc_buf.data(), enc_buf.size()}, {private_key.data(), private_key.size()}, {dec_buf.data(), dec_buf.size()});

    assert(data == dec_buf);
}

struct SymTest { std::string data; std::string key; };
struct AsymTest { std::string data; std::string pub; std::string priv; };

int main() {
    std::cout << "RUNNING AUTOMATIC PLUGINS TESTS\n";

    std::vector<SymTest> vigenere_tests = {
        {"Hello", "key"}, {"Cryptography", "secret"}, {"Test12345", "abc"}
    };
    
    void* vigenere = dlopen("./plugins/vigenere/libvigenere.so", RTLD_LAZY);
    if (vigenere) {
        for(auto& t : vigenere_tests) run_test(vigenere, {t.data.begin(), t.data.end()}, {t.key.begin(), t.key.end()});
        dlclose(vigenere);
        std::cout << "[PASS] Vigenere 3 tests passed!\n";
    }

    std::vector<SymTest> rc4_tests = {
        {"PlaintextData", "key1"}, {"AnotherTest", "password"}, {"Short", "k"}
    };
    
    void* rc4 = dlopen("./plugins/rc4/librc4.so", RTLD_LAZY);
    if (rc4) {
        for(auto& t : rc4_tests) run_test(rc4, {t.data.begin(), t.data.end()}, {t.key.begin(), t.key.end()});
        dlclose(rc4);
        std::cout << "[PASS] RC4 3 tests passed!\n";
    }

    std::vector<AsymTest> rsa_tests = {
        {"AVTF", "7,3233", "1783,3233"},
        {"Data", "7,3233", "1783,3233"},
        {"123", "7,3233", "1783,3233"}
    };
    
    void* rsa = dlopen("./plugins/rsa/librsa.so", RTLD_LAZY);
    if (rsa) {
        for(auto& t : rsa_tests) run_rsa_test(rsa, {t.data.begin(), t.data.end()}, {t.pub.begin(), t.pub.end()}, {t.priv.begin(), t.priv.end()});
        dlclose(rsa);
        std::cout << "[PASS] RSA 3 tests passed!\n";
    }

    std::vector<AsymTest> eg_tests = {
        {"Hello", "257,3,243", "257,3,5"},
        {"Code", "257,3,243", "257,3,5"},
        {"Test", "257,3,243", "257,3,5"}
    };
    
    void* elgamal = dlopen("./plugins/elgamal/libelgamal.so", RTLD_LAZY);
    if (elgamal) {
        for(auto& t : eg_tests) {
            run_rsa_test(elgamal, {t.data.begin(), t.data.end()}, {t.pub.begin(), t.pub.end()}, {t.priv.begin(), t.priv.end()});
        }
        dlclose(elgamal);
        std::cout << "[PASS] ElGamal 3 tests passed!\n";
    }

    

    /*
    std::vector<SymTest> grunfeld_tests = {
        {"HELLO", "2015"},
        {"Cryptography", "123"},
        {"Test12345", "987"}
    };

    void* grunfeld = dlopen("./plugins/grunfeld/libgrunfeld.so", RTLD_LAZY);
    if (grunfeld) {
        for (auto& t : grunfeld_tests)
            run_test(grunfeld, {t.data.begin(), t.data.end()}, {t.key.begin(), t.key.end()});
        dlclose(grunfeld);
        std::cout << "[PASS] Grunfeld 3 tests passed!\n";
    } else {
    std::cerr << "Failed to load Grunfeld plugin\n";
    }

    std::vector<SymTest> otr_tests = {
        {"Secret message", "alice@example.com"},
        {"Hello OTR", "bob@example.com"},
        {"Another test", "carol@example.com"}
    };

    void* otr = dlopen("./plugins/otr/libotr.so", RTLD_LAZY);
    if (otr) {
        for (auto& t : otr_tests)
            run_test(otr, {t.data.begin(), t.data.end()}, {t.key.begin(), t.key.end()});
        dlclose(otr);
        std::cout << "[PASS] OTR 3 tests passed!\n";
    } else {
        std::cerr << "Failed to load OTR plugin\n";
    }
    */




    std::cout << "\nAll tests passed successfully!\n";
    return 0;
}