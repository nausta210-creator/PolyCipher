#include "crypto_interface.h"

// Безопасное физическое зануление памяти (очистка ключей/данных после использования)
void secure_mem_clear(uint8_t* ptr, size_t size) {
    if (ptr) {
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *vptr++ = 0;
        }
    }
}

extern "C" {

// 1. Возвращает необходимый размер выходного буфера
CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    
    // В шифре Виженера размер зашифрованного файла строго равен размеру исходного
    *out_size = input_size;
    return CryptoStatus::Success;
}

// 2. Функция зашифрования (Прямое побайтовое гаммирование по модулю 256)
CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    // Строгая проверка входных параметров на корректность
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size) {
        return CryptoStatus::BufferTooSmall;
    }

    // Бегаем по каждому байту файла (картинки, текста или mp3)
    for (size_t i = 0; i < input.size; ++i) {
        uint8_t text_byte = input.data[i];
        uint8_t key_byte = key.data[i % key.size]; // Ключ повторяется циклически
        
        // Складываем байты по модулю 256
        output.data[i] = static_cast<uint8_t>((text_byte + key_byte) % 256);
    }

    return CryptoStatus::Success;
}

// 3. Функция расшифрования (Обратное побайтовое гаммирование)
CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size) {
        return CryptoStatus::BufferTooSmall;
    }

    for (size_t i = 0; i < input.size; ++i) {
        uint8_t cipher_byte = input.data[i];
        uint8_t key_byte = key.data[i % key.size];
        
        // Вычитаем байт ключа. Добавляем 256, чтобы избежать ухода в минус до взятия остатка
        output.data[i] = static_cast<uint8_t>((cipher_byte - key_byte + 256) % 256);
    }

    return CryptoStatus::Success;
}

} // extern "C"