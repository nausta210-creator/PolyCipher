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

int main() {
    void* vigenere = dlopen("./plugins/vigenere/libvigenere.so", RTLD_LAZY);
    if (vigenere) {
        run_test(vigenere, {1, 2, 3, 4, 5}, {4, 2});
        dlclose(vigenere);
        std::cout << "Vigenere tests passed successfully!\n";
    }
    return 0;
}