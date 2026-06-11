#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <cstring>
#include <dlfcn.h> // Системная библиотека Linux для динамической загрузки (.so)

#include "crypto_interface.h"

// Перечисление для режимов работы (замена switch-case на enum class)
enum class CryptoAction : int32_t {
    Encrypt,
    Decrypt,
    Unknown
};

// Функция для безопасного зануления векторов с секретными данными
void secure_vector_clear(std::vector<uint8_t>& vec) {
    volatile uint8_t* p = vec.data();
    size_t size = vec.size();
    while (size--) {
        *p++ = 0;
    }
    vec.clear();
}

int main(int argc, char* argv[]) {
    // 1. ПРИМИТИВНЫЙ ПАРСИНГ CLI (для демонстрации архитектуры)
    // В реальном проекте здесь будет полноценный разбор флагов -m, -a, -k, -f
    if (argc < 6) {
        std::cerr << "Использование: " << argv[0] 
                  << " <action: enc/dec> <path_to_plugin.so> <key> <input_file> <output_file>\n";
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    std::string action_str = argv[1];
    std::string plugin_path = argv[2];
    std::string key_str = argv[3];
    std::string input_path = argv[4];
    std::string output_path = argv[5];

    CryptoAction action = CryptoAction::Unknown;
    if (action_str == "enc") action = CryptoAction::Encrypt;
    if (action_str == "dec") action = CryptoAction::Decrypt;

    if (action == CryptoAction::Unknown) {
        std::cerr << "Ошибка: Неизвестное действие (используйте 'enc' или 'dec')\n";
        return static_cast<int32_t>(CryptoStatus::InvalidParam);
    }

    // 2. ДИНАМИЧЕСКАЯ ЗАГРУЗКА БИБЛИОТЕКИ (.so)
    void* handle = dlopen(plugin_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Ошибка загрузки библиотеки: " << dlerror() << "\n";
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    // 3.ОПРЕДЕЛЕНИЕ СИГНАТУР ФУНКЦИЙ (Указатели на функции из C ABI)
    using GetSizeFunc = CryptoStatus(*)(size_t, size_t*, bool);
    using CryptoFunc = CryptoStatus(*)(ConstBuffer, ConstBuffer, MutBuffer);

    // Вытаскиваем функции по их именам из ТЗ
    GetSizeFunc get_output_size = reinterpret_cast<GetSizeFunc>(dlsym(handle, "get_output_size"));
    CryptoFunc encrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "encrypt"));
    CryptoFunc decrypt = reinterpret_cast<CryptoFunc>(dlsym(handle, "decrypt"));

    if (!get_output_size || !encrypt || !decrypt) {
        std::cerr << "Ошибка: Не удалось найти требуемые функции в плагине.\n";
        dlclose(handle);
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    // 4. ПОБАЙТОВОЕ ЧТЕНИЕ ФАЙЛА ЛЮБОГО ТИПА (Бинарный режим)
    std::ifstream infile(input_path, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Ошибка: Не удалось открыть входной файл.\n";
        dlclose(handle);
        return static_cast<int32_t>(CryptoStatus::UnknownError);
    }

    std::vector<uint8_t> input_bytes((std::istreambuf_iterator<char>(infile)), 
                                      std::istreambuf_iterator<char>());
    infile.close();

    // Подготовка ключа в байтах
    std::vector<uint8_t> key_bytes(key_str.begin(), key_str.end());

    // 5.БЕЗОПАСНОЕ ВЫДЕЛЕНИЕ ПАМЯТИ ПОД ВЫХОД
    size_t required_output_size = 0;
    bool is_encrypt = (action == CryptoAction::Encrypt);
    
    CryptoStatus status = get_output_size(input_bytes.size(), &required_output_size, is_encrypt);
    if (status != CryptoStatus::Success) {
        std::cerr << "Ошибка при расчете размера выходного буфера.\n";
        dlclose(handle);
        return static_cast<int32_t>(status);
    }

    std::vector<uint8_t> output_bytes(required_output_size);

    // Буферы для передачи через C ABI
    ConstBuffer in_buf { input_bytes.data(), input_bytes.size() };
    ConstBuffer key_buf { key_bytes.data(), key_bytes.size() };
    MutBuffer out_buf { output_bytes.data(), output_bytes.size() };

    // 6. ВЫПОЛНЕНИЕ ОПЕРАЦИИ БЕЗ SWITCH-CASE (Строгая обработка состояний)
    if (action == CryptoAction::Encrypt) {
        status = encrypt(in_buf, key_buf, out_buf);
    } else if (action == CryptoAction::Decrypt) {
        status = decrypt(in_buf, key_buf, out_buf);
    }

    if (status != CryptoStatus::Success) {
        std::cerr << "Криптографическая операция завершилась ошибкой с кодом: " 
                  << static_cast<int32_t>(status) << "\n";
        secure_vector_clear(input_bytes);
        secure_vector_clear(key_bytes);
        secure_vector_clear(output_bytes);
        dlclose(handle);
        return static_cast<int32_t>(status);
    }

    // 7. ЗАПИСЬ РЕЗУЛЬТАТА НА ДИСК
    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Ошибка: Не удалось открыть файл для записи.\n";
        status = CryptoStatus::MemoryError;
    } else {
        outfile.write(reinterpret_cast<const char*>(output_bytes.data()), output_bytes.size());
        outfile.close();
        std::cout << "Операция успешно завершена! Файл сохранен.\n";
    }

    // 8. ОБЯЗАТЕЛЬНОЕ ЗАНУЛЕНИЕ ПАМЯТИ ПЕРЕД ВЫХОДОМ (Требование безопасности!)
    secure_vector_clear(input_bytes);
    secure_vector_clear(key_bytes);
    secure_vector_clear(output_bytes);

    // Выгружаем библиотеку
    dlclose(handle);

    return static_cast<int32_t>(status);
}