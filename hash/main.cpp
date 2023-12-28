#include <iostream>
#include <fstream>
#include <cryptlib.h>
#include <sha.h>

using namespace std;
using namespace CryptoPP;

int main()
{
    try {
        // Открытие файла для чтения
        ifstream file("test.txt", ios::binary);
        if (!file) {
            throw runtime_error("Ошибка открытия файла");
        }

        // Вычисление хэш-функции
        SHA256 hash;
        byte buffer[4096];
        while (file.good()) {
            file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
            size_t count = file.gcount();
            if (count > 0) {
                hash.Update(buffer, count);
            }
        }
        file.close();

        // Получение результата хэширования
        byte digest[hash.DigestSize()];
        hash.Final(digest);

        // Вывод результата на экран
        cout << "Хэш-функция: ";
        for (size_t i = 0; i < sizeof(digest); i++) {
            printf("%02x", digest[i]);
        }
        cout << endl;

    } catch (exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
