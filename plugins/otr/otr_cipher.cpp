#include "../../include/crypto_interface.h"
#include <cstring>
#include <vector>
#include <map>
#include <random>

using namespace std;

static map<string, vector<uint8_t>> session_keys;
static map<string, bool> secure_sessions;

static void xor_crypt(const uint8_t* input, size_t len, const vector<uint8_t>& key, uint8_t* output) {
    for (size_t i = 0; i < len; ++i)
        output[i] = input[i] ^ key[i % key.size()];
}

static vector<uint8_t> generate_key(const string& id) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dis(0, 255);
    vector<uint8_t> key(32);
    for (int i = 0; i < 32; ++i) key[i] = dis(gen);
    return key;
}

static string parse_key(const uint8_t* data, size_t size) {
    return string((char*)data, size);
}

extern "C" {

CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    *out_size = input_size;
    return CryptoStatus::Success;
}

CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    string recipient = parse_key(key.data, key.size);
    if (recipient.empty()) return CryptoStatus::InvalidParam;
    if (!secure_sessions[recipient]) {
        session_keys[recipient] = generate_key(recipient);
        secure_sessions[recipient] = true;
    }
    size_t need; get_output_size(input.size, &need, true);
    if (output.size < need) return CryptoStatus::BufferTooSmall;
    xor_crypt(input.data, input.size, session_keys[recipient], output.data);
    return CryptoStatus::Success;
}

CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    string sender = parse_key(key.data, key.size);
    if (sender.empty()) return CryptoStatus::InvalidParam;
    if (!secure_sessions[sender]) return CryptoStatus::AuthFailure;
    size_t need; get_output_size(input.size, &need, false);
    if (output.size < need) return CryptoStatus::BufferTooSmall;
    xor_crypt(input.data, input.size, session_keys[sender], output.data);
    return CryptoStatus::Success;
}

const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo info = { "OTR", 0 };
    return &info;
}

}