#include "crypto_interface.h"
#include <algorithm>
#include <string>
#include <cstdio>
#include <iostream>

// Безопасное зануление памяти
void secure_rsa_clear(uint8_t* ptr, size_t size) {
    if (ptr) {
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *vptr++ = 0;
        }
    }
}

// Функция быстрого возведения в степень по модулю: (base^exp) % mod
uint64_t modular_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 1) return 0;
    uint64_t res = 1;
    base = base % mod;
    
    while (exp > 0) {
        // Если текущий бит экспоненты равен 1, умножаем результат
        if (exp % 2 == 1) {
            res = (static_cast<__uint128_t>(res) * base) % mod;
        }
        // Сдвигаем экспоненту и возводим базу в квадрат
        exp = exp >> 1; // или exp /= 2;
        base = (static_cast<__uint128_t>(base) * base) % mod;
    }
    return res;
}

// Расширенный алгоритм Евклида с переменными u и v для поиска обратного элемента
// e * u + phi * v = 1
int64_t extended_gcd(int64_t e, int64_t phi) {
    // Строка таблицы i = 0 (Начальные условия)
    int64_t r0 = phi;
    int64_t u0 = 0;
    int64_t v0 = 1;

    // Строка таблицы i = 1 (Начальные условия)
    int64_t r1 = e;
    int64_t u1 = 1;
    int64_t v1 = 0;

    // Переменные текущей строки (i >= 2)
    size_t i = 2; 
    int64_t q = 0;   // Колонка 2: Неполное частное
    int64_t r = 0;   // Колонка 3: Остаток
    int64_t u = 0;   // Колонка 4: Переменная u
    int64_t v = 0;   // Колонка 5: Переменная v

    while (r1 != 0) {
        // Вычисления строго по порядку столбцов таблицы:
        q = r0 / r1;      // 1. Считаем q_i (деление нацело)
        r = r0 % r1;      // 2. Считаем r_i (остаток)
        u = u0 - q * u1;  // 3. Считаем u_i
        v = v0 - q * v1;  // 4. Считаем v_i

        // Сдвиг состояний (готовимся к следующей строке i++)
        r0 = r1; r1 = r;
        u0 = u1; u1 = u;
        v0 = v1; v1 = v;
        
        i++;
    }

    // Результат (переменная u из строки перед нулевым остатком)
    if (u0 < 0) {
        u0 += phi; // Приведение к положительному вычету
    }
    
    return u0;
}

extern "C" {

// 1. Расчет размера буфера (Для RSA блоки данных могут увеличиваться до размера модуля)
CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    
    if (is_encrypt) {
        // При шифровании каждый байт превращается в 8-байтовое число (uint64_t)
        *out_size = input_size * sizeof(uint64_t);
    } else {
        // При расшифровании каждые 8 байт превращаются обратно в 1 байт
        *out_size = input_size / sizeof(uint64_t);
    }
    return CryptoStatus::Success;
}

// 2. Функция зашифрования RSA (Поблочно берем байты и возводим в степень e по модулю n)
CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size * sizeof(uint64_t)) {
        return CryptoStatus::BufferTooSmall;
    }

    std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
    
    uint64_t e = 0, n = 0;
    // Используем явный вызов sscanf
    if (std::sscanf(key_str.c_str(), "%lu,%lu", &e, &n) != 2) {
        return CryptoStatus::InvalidParam;
    }

    std::cout << "[RSA DEBUG] Ключ успешно прочитан: e = " << e << ", n = " << n << "\n";

    uint64_t* out_ptr = reinterpret_cast<uint64_t*>(output.data);

    for (size_t i = 0; i < input.size; ++i) {
        uint64_t m = input.data[i];
        if (m >= n) {
            return CryptoStatus::InvalidParam;
        }
        out_ptr[i] = modular_pow(m, e, n);
    }

    return CryptoStatus::Success;
}

// 3. Функция расшифрования RSA
CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (input.size % sizeof(uint64_t) != 0 || output.size < input.size / sizeof(uint64_t)) {
        return CryptoStatus::BufferTooSmall;
    }

    std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
    
    uint64_t d = 0, n = 0;
    if (std::sscanf(key_str.c_str(), "%lu,%lu", &d, &n) != 2) {
        return CryptoStatus::InvalidParam;
    }

    const uint64_t* in_ptr = reinterpret_cast<const uint64_t*>(input.data);
    size_t blocks_count = input.size / sizeof(uint64_t);

    for (size_t i = 0; i < blocks_count; ++i) {
        uint64_t c = in_ptr[i];
        output.data[i] = static_cast<uint8_t>(modular_pow(c, d, n) & 0xFF);
    }

    return CryptoStatus::Success;
}

} // extern "C"