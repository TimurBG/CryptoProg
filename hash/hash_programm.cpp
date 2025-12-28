#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

using namespace std;
using namespace CryptoPP;

// Функция для вычисления хэша файла
string CalculateFileHash(const string& filename, const string& hashAlgorithm) {
    string digest;
    
    if (hashAlgorithm == "SHA1") {
        SHA1 hash;
        FileSource(filename.c_str(), true, 
            new HashFilter(hash, 
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
    }
    else if (hashAlgorithm == "SHA256") {
        SHA256 hash;
        FileSource(filename.c_str(), true, 
            new HashFilter(hash, 
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
    }
    else if (hashAlgorithm == "SHA512") {
        SHA512 hash;
        FileSource(filename.c_str(), true, 
            new HashFilter(hash, 
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
    }
    else if (hashAlgorithm == "SHA3_256") {
        SHA3_256 hash;
        FileSource(filename.c_str(), true, 
            new HashFilter(hash, 
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
    }
    else {
        throw runtime_error("Неподдерживаемый алгоритм хэширования");
    }
    
    return digest;
}

int main() {
    cout << "=== Программа вычисления хэш-функции файла ===" << endl;
    
    try {
        string filename, hashAlgorithm;
        
        // Ввод данных
        cout << "Введите имя файла: ";
        cin >> filename;
        
        cout << "Доступные алгоритмы хэширования:" << endl;
        cout << "1. SHA1" << endl;
        cout << "2. SHA256" << endl;
        cout << "3. SHA512" << endl;
        cout << "4. SHA3-256" << endl;
        cout << "Выберите алгоритм (введите название): ";
        cin >> hashAlgorithm;
        
        // Проверка существования файла
        ifstream file(filename);
        if (!file) {
            cerr << "Ошибка: Файл '" << filename << "' не найден!" << endl;
            return 1;
        }
        file.close();
        
        // Вычисление хэша
        string hash = CalculateFileHash(filename, hashAlgorithm);
        
        // Вывод результата
        cout << "\nРезультат вычисления хэш-функции:" << endl;
        cout << "Файл: " << filename << endl;
        cout << "Алгоритм: " << hashAlgorithm << endl;
        cout << "Хэш: " << hash << endl;
        
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
