#include "../../include/crypto_interface.h"
#include <cstring>
#include <cctype>
#include <vector>
#include <random>

using namespace std;

static int charToInt(char c) {
    return toupper(c) - 'A';
}

static char intToChar(int n) {
    return 'A' + (n % 26);
}

static bool isLatinLetter(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static vector<int> parseKey(const uint8_t* key_data, size_t key_size) {
    vector<int> key;
    for (size_t i = 0; i < key_size; ++i) {
        if (isdigit(key_data[i])) {
            key.push_back(key_data[i] - '0');
        }
    }
    return key;
}

static string gruensfeldCipher(const string& text, const vector<int>& key, bool encrypt) {
    string result;
    int keyIndex = 0;
    int keyLen = key.size();
    if (keyLen == 0) return text;

    for (char ch : text) {
        if (isLatinLetter(ch)) {
            int charNum = charToInt(ch);
            int shift = key[keyIndex % keyLen];
            int newCharNum;
            if (encrypt) newCharNum = (charNum + shift) % 26;
            else newCharNum = (charNum - shift + 26) % 26;
            char newChar = intToChar(newCharNum);
            result += (islower(ch) ? tolower(newChar) : newChar);
            keyIndex++;
        } else {
            result += ch;
        }
    }
    return result;
}

extern "C" {

CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    *out_size = input_size;
    return CryptoStatus::Success;
}

CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    vector<int> keyVec = parseKey(key.data, key.size);
    if (keyVec.empty()) return CryptoStatus::InvalidParam;
    size_t need; get_output_size(input.size, &need, true);
    if (output.size < need) return CryptoStatus::BufferTooSmall;
    string plaintext((char*)input.data, input.size);
    string ciphertext = gruensfeldCipher(plaintext, keyVec, true);
    memcpy(output.data, ciphertext.data(), ciphertext.size());
    return CryptoStatus::Success;
}

CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    vector<int> keyVec = parseKey(key.data, key.size);
    if (keyVec.empty()) return CryptoStatus::InvalidParam;
    size_t need; get_output_size(input.size, &need, false);
    if (output.size < need) return CryptoStatus::BufferTooSmall;
    string ciphertext((char*)input.data, input.size);
    string plaintext = gruensfeldCipher(ciphertext, keyVec, false);
    memcpy(output.data, plaintext.data(), plaintext.size());
    return CryptoStatus::Success;
}

const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo info = { "Grunfeld", 0 };
    return &info;
}

CryptoStatus generate_grunfeld_keys(char* buffer, size_t max_len, size_t* bytes_written) {
    if (!buffer || !bytes_written) return CryptoStatus::InvalidParam;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 9);
    string key;
    for (int i = 0; i < 10; ++i) key += to_string(dis(gen));
    if (key.size() + 1 > max_len) return CryptoStatus::BufferTooSmall;
    strcpy(buffer, key.c_str());
    *bytes_written = key.size();
    return CryptoStatus::Success;
}

}