#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

// Функция для получения пароля от пользователя
std::string GetPassword() {
    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);
    return password;
}

// Функция для генерации ключа из пароля
void DeriveKey(const std::string& password, byte* key, size_t keySize, byte* salt, size_t saltSize) {
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, keySize, 0, (byte*)password.data(), password.size(), salt, saltSize, 1024, 0.0);
}

// Функция шифрования/дешифрования файла
void ProcessFile(const std::string& inputFile, const std::string& outputFile, 
                 const std::string& algorithm, bool encrypt, const std::string& password) {
    try {
        // Генерация соли
        AutoSeededRandomPool prng;
        byte salt[8];
        prng.GenerateBlock(salt, sizeof(salt));
        
        // Определение параметров алгоритма
        size_t keySize = 0;
        size_t blockSize = 0;
        
        if (algorithm == "AES") {
            keySize = AES::DEFAULT_KEYLENGTH; // 16 байт для AES-128
            blockSize = AES::BLOCKSIZE;
        } else if (algorithm == "DES") {
            keySize = DES::DEFAULT_KEYLENGTH; // 8 байт для DES
            blockSize = DES::BLOCKSIZE;
        }
        
        // Генерация ключа из пароля
        byte key[keySize];
        DeriveKey(password, key, keySize, salt, sizeof(salt));
        
        // Генерация IV
        byte iv[blockSize];
        prng.GenerateBlock(iv, sizeof(iv));
        
        // Чтение входного файла
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Не удалось открыть входной файл: " + inputFile);
        }
        
        std::string inputData((std::istreambuf_iterator<char>(inFile)), 
                              std::istreambuf_iterator<char>());
        inFile.close();
        
        std::string outputData;
        
        if (encrypt) {
            // ШИФРОВАНИЕ
            std::cout << "Шифрование файла..." << std::endl;
            
            if (algorithm == "AES") {
                CBC_Mode<AES>::Encryption encryptor;
                encryptor.SetKeyWithIV(key, keySize, iv, blockSize);
                
                StringSource ss(inputData, true,
                    new StreamTransformationFilter(encryptor,
                        new StringSink(outputData)
                    )
                );
            } else if (algorithm == "DES") {
                CBC_Mode<DES>::Encryption encryptor;
                encryptor.SetKeyWithIV(key, keySize, iv, blockSize);
                
                StringSource ss(inputData, true,
                    new StreamTransformationFilter(encryptor,
                        new StringSink(outputData)
                    )
                );
            }
            
            // Запись соли, IV и зашифрованных данных в выходной файл
            std::ofstream outFile(outputFile, std::ios::binary);
            outFile.write((char*)salt, sizeof(salt));
            outFile.write((char*)iv, sizeof(iv));
            outFile.write(outputData.c_str(), outputData.size());
            outFile.close();
            
            std::cout << "Файл зашифрован и сохранен как: " << outputFile << std::endl;
            
        } else {
            // ДЕШИФРОВАНИЕ
            std::cout << "Дешифрование файла..." << std::endl;
            
            // Проверка размера файла
            if (inputData.size() < sizeof(salt) + sizeof(iv)) {
                throw std::runtime_error("Файл слишком мал для дешифрования");
            }
            
            // Извлечение соли и IV из начала файла
            size_t offset = 0;
            memcpy(salt, inputData.data() + offset, sizeof(salt));
            offset += sizeof(salt);
            memcpy(iv, inputData.data() + offset, sizeof(iv));
            offset += sizeof(iv);
            
            // Регенерация ключа из пароля и соли
            DeriveKey(password, key, keySize, salt, sizeof(salt));
            
            // Дешифрование данных
            std::string encryptedData = inputData.substr(offset);
            
            if (algorithm == "AES") {
                CBC_Mode<AES>::Decryption decryptor;
                decryptor.SetKeyWithIV(key, keySize, iv, blockSize);
                
                StringSource ss(encryptedData, true,
                    new StreamTransformationFilter(decryptor,
                        new StringSink(outputData)
                    )
                );
            } else if (algorithm == "DES") {
                CBC_Mode<DES>::Decryption decryptor;
                decryptor.SetKeyWithIV(key, keySize, iv, blockSize);
                
                StringSource ss(encryptedData, true,
                    new StreamTransformationFilter(decryptor,
                        new StringSink(outputData)
                    )
                );
            }
            
            // Запись дешифрованных данных
            std::ofstream outFile(outputFile, std::ios::binary);
            outFile.write(outputData.c_str(), outputData.size());
            outFile.close();
            
            std::cout << "Файл дешифрован и сохранен как: " << outputFile << std::endl;
        }
        
    } catch (const Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "=== Программа шифрования/дешифрования файлов ===" << std::endl;
    std::cout << "Поддерживаемые алгоритмы: AES, DES" << std::endl;
    
    // Выбор алгоритма
    std::string algorithm;
    while (true) {
        std::cout << "\nВыберите алгоритм (AES/DES): ";
        std::getline(std::cin, algorithm);
        
        if (algorithm == "AES" || algorithm == "DES") {
            break;
        }
        std::cout << "Неверный выбор. Пожалуйста, введите AES или DES." << std::endl;
    }
    
    // Выбор операции
    std::string operation;
    while (true) {
        std::cout << "Выберите операцию (encrypt/decrypt): ";
        std::getline(std::cin, operation);
        
        if (operation == "encrypt" || operation == "decrypt") {
            break;
        }
        std::cout << "Неверный выбор. Пожалуйста, введите encrypt или decrypt." << std::endl;
    }
    
    bool encrypt = (operation == "encrypt");
    
    // Ввод имен файлов
    std::string inputFile, outputFile;
    
    std::cout << "Введите имя входного файла: ";
    std::getline(std::cin, inputFile);
    
    std::cout << "Введите имя выходного файла: ";
    std::getline(std::cin, outputFile);
    
    // Получение пароля
    std::string password = GetPassword();
    
    // Обработка файла
    ProcessFile(inputFile, outputFile, algorithm, encrypt, password);
    
    return 0;
}
