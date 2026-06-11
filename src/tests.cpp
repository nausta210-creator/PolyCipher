#include <iostream>
#include <cassert>
#include <vector>
#include <dlfcn.h>
#include "crypto_interface.h"

void run_test(void* handle, const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    using GetSizeFunc = CryptoStatus(*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus(*)(ConstBuffer, ConstBuffer, MutBuffer);

    GetSizeFunc get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    CryptoFunc encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    CryptoFunc decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    assert(get_output_size && encrypt && decrypt);

    size_t enc_size = 0;
    CryptoStatus status = get_output_size(data.size(), &enc_size, true);
    assert(status == CryptoStatus::Success);
    
    std::vector<uint8_t> enc_buf(enc_size);
    status = encrypt({data.data(), data.size()}, {key.data(), key.size()}, {enc_buf.data(), enc_buf.size()});
    assert(status == CryptoStatus::Success);

    size_t dec_size = 0;
    status = get_output_size(enc_buf.size(), &dec_size, false);
    assert(status == CryptoStatus::Success);
    
    std::vector<uint8_t> dec_buf(dec_size);
    status = decrypt({enc_buf.data(), enc_buf.size()}, {key.data(), key.size()}, {dec_buf.data(), dec_buf.size()});
    assert(status == CryptoStatus::Success);

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
    CryptoStatus status = encrypt({data.data(), data.size()}, {public_key.data(), public_key.size()}, {enc_buf.data(), enc_buf.size()});
    assert(status == CryptoStatus::Success);

    size_t dec_size = 0;
    get_output_size(enc_buf.size(), &dec_size, false);
    std::vector<uint8_t> dec_buf(dec_size);
    status = decrypt({enc_buf.data(), enc_buf.size()}, {private_key.data(), private_key.size()}, {dec_buf.data(), dec_buf.size()});
    assert(status == CryptoStatus::Success);

    assert(data == dec_buf);
}

int main() {
    std::cout << "RUNNING AUTOMATIC PLUGINS TESTS\n";

    void* vigenere = dlopen("./plugins/vigenere/libvigenere.so", RTLD_LAZY);
    if (!vigenere) {
        std::cerr << "Failed to load Vigenere plugin for tests: " << dlerror() << "\n";
        return 1;
    }
    run_test(vigenere, {'H', 'e', 'l', 'l', 'o'}, {'k', 'e', 'y'});
    dlclose(vigenere);
    std::cout << "[PASS] Vigenere tests passed successfully!\n";

    void* rsa = dlopen("./plugins/rsa/librsa.so", RTLD_LAZY);
    if (!rsa) {
        std::cerr << "Failed to load RSA plugin for tests: " << dlerror() << "\n";
        return 1;
    }
    
    std::string pub_key = "7,3233";   
    std::string priv_key = "1783,3233"; 
    
    std::vector<uint8_t> rsa_pub(pub_key.begin(), pub_key.end());
    std::vector<uint8_t> rsa_priv(priv_key.begin(), priv_key.end());
    
    run_rsa_test(rsa, {'A', 'V', 'T', 'F'}, rsa_pub, rsa_priv);
    dlclose(rsa);
    std::cout << "[PASS] RSA tests passed successfully!\n";

    std::cout << "All tests passed completely!\n";
    return 0;
}