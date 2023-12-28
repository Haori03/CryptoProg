#include <iostream>
#include <fstream>
#include <cryptlib.h>
#include <modes.h>
#include <aes.h>
#include <sha.h>

using namespace std;
using namespace CryptoPP;

void encrypt(const string& password, const string& input_file, const string& output_file)
{
    try {
        // Открытие файлов для чтения и записи
        ifstream in(input_file, ios::binary);
        if (!in) {
            throw runtime_error("Ошибка открытия файла для чтения");
        }
        ofstream out(output_file, ios::binary);
        if (!out) {
            throw runtime_error("Ошибка открытия файла для записи");
        }

        // Вычисление ключа шифрования из пароля
        byte key[AES::DEFAULT_KEYLENGTH];
        SHA256 hash;
        hash.Update(reinterpret_cast<const byte*>(password.data()), password.size());
        hash.Final(key);

        // Инициализация шифрования в режиме CBC
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE);
        CBC_Mode<AES>::Encryption encryption(key, sizeof(key), iv);

        // Шифрование данных
        byte buffer[4096];
        while (in.good()) {
            in.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
            size_t count = in.gcount();
            if (count > 0) {
                encryption.ProcessData(buffer, buffer, count);
                out.write(reinterpret_cast<const char*>(buffer), count);
            }
        }

        // Закрытие файлов
        in.close();
        out.close();

        cout << "Шифрование завершено" << endl;

    } catch (exception& e) {
        cerr << e.what() << endl;
    }
}

void decrypt(const string& password, const string& input_file, const string& output_file)
{
    try {
        // Открытие файлов для чтения и записи
        ifstream in(input_file, ios::binary);
        if (!in) {
            throw runtime_error("Ошибка открытия файла для чтения");
        }
        ofstream out(output_file, ios::binary);
        if (!out) {
            throw runtime_error("Ошибка открытия файла для записи");
        }

        // Вычисление ключа шифрования из пароля
        byte key[AES::DEFAULT_KEYLENGTH];
        SHA256 hash;
        hash.Update(reinterpret_cast<const byte*>(password.data()), password.size());
        hash.Final(key);

        // Инициализация расшифрования в режиме CBC
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE);
        CBC_Mode<AES>::Decryption decryption(key, sizeof(key), iv);

        // Расшифрование данных
        byte buffer[4096];
        while (in.good()) {
            in.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
            size_t count = in.gcount();
            if (count > 0) {
                decryption.ProcessData(buffer, buffer, count);
                out.write(reinterpret_cast<const char*>(buffer), count);
            }
        }

        // Закрытие файлов
        in.close();
        out.close();

        cout << "Расшифрование завершено" << endl;

    } catch (exception& e) {
        cerr << e.what() << endl;
    }
}

int main()
{
    // Выбор режима работы
    cout << "Выберите режим работы (1 - зашифрование, 2 - расшифрование): ";
    int mode;
    cin >> mode;

    // Ввод пароля
    cout << "Введите пароль: ";
    string password;
    cin >> password;

    // Выбор файлов
    cout << "Введите имя файла с исходными данными: ";
    string input_file;
    cin >> input_file;
    cout << "Введите имя файла для записи результата: ";
    string output_file;
    cin >> output_file;

    // Запуск шифрования/расшифрования
    if (mode == 1) {
        encrypt(password, input_file, output_file);
    } else if (mode == 2) {
        decrypt(password, input_file, output_file);
    } else {
        cerr << "Неверный режим работы" << endl;
        return 1;
    }

    return 0;
}
