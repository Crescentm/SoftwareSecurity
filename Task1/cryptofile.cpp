#include <cstdio>
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <wtypes.h>

#include <cstring>
#include <direct.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <windows.h>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

using namespace std;

byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

void initKV(const char *password) {
  memset(key, atol(password), CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
}

string encrypt(string filename) {
  string plainText;
  string cipherText;
  ifstream in(filename, ios::in | ios::binary);
  string line;
  while (getline(in, line)) {
    if (line.length() > 1) {
      plainText += line + "\n";
    }
    line.clear();
  }

  //
  CryptoPP::AES::Encryption aesEncryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
                                                              iv);
  CryptoPP::StreamTransformationFilter stfEncryptor(
      cbcEncryption, new CryptoPP::StringSink(cipherText));
  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(plainText.c_str()),
                   plainText.length() + 1);
  stfEncryptor.MessageEnd();

  string cipherTextHex;
  for (int i = 0; i < cipherText.size(); i++) {
    char ch[3] = {0};
    sprintf(ch, "%02x", static_cast<byte>(cipherText[i]));
    cipherTextHex += ch;
  }
  return cipherTextHex;

  // CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;e.SetKeyWithIV(key,
  // CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

  // CryptoPP::StringSource s(plainText, true,new
  // CryptoPP::StreamTransformationFilter(e,new
  // CryptoPP::StringSink(cipherText))
  // // StreamTransformationFilter
  //); // StringSource
  /*return cipherText;*/
}

void writeCipher(string output, string filename) {
  ofstream out;
  const char *c_s = filename.c_str();
  out.open(c_s, ios::out | ios::binary);
  if (!out) {
    cout << "error: can not open this file\n";
    return;
  }
  int filelength = output.length();
  char s;
  for (int index = 0; index < filelength; index++) {
    s = output[index];
    out.write(&s, sizeof(s));
  }
  // out.write(output.c_str(), output.length());
  out.close();
  return;

  // cout << "writeCipher finish " << endl << endl;
}

string decrypt(string cipherTextHex) {
  string cipherText;
  string decryptedText;
  int i = 0;
  while (true) {
    char c;
    int x;
    stringstream ss;
    ss << hex << cipherTextHex.substr(i, 2).c_str();
    ss >> x;
    c = (char)x;
    cipherText += c;
    if (i >= cipherTextHex.length() - 2)
      break;
    i += 2;
  }

  //
  CryptoPP::AES::Decryption aesDecryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption,
                                                              iv);
  CryptoPP::StreamTransformationFilter stfDecryptor(
      cbcDecryption, new CryptoPP::StringSink(decryptedText));
  stfDecryptor.Put(reinterpret_cast<const unsigned char *>(cipherText.c_str()),
                   cipherText.size());

  stfDecryptor.MessageEnd();

  // CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d;
  // d.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

  // CryptoPP::StringSource s(cipherTextHex, true,
  //    new CryptoPP::StreamTransformationFilter(d,
  //        new CryptoPP::StringSink(decryptedText)
  //    ) // StreamTransformationFilter
  //); // StringSource

  return decryptedText;
}

string readCipher(string filename) {
  ifstream in(filename, ios::in | ios::binary);
  string line;
  string decryptedText;
  while (getline(in, line)) {
    if (line.length() > 1) {
      decryptedText += decrypt(line) + "\n";
    }
    line.clear();
  }

  // cout << "readCipher finish " << endl;
  in.close();
  return decryptedText;
}

void findfile(int index, char *dir) {

  char dirNew[100];
  strcpy(dirNew, dir);
  strcat(dirNew, "\\");
  strcat(dirNew, "*.*");
  HANDLE hFind;
  WIN32_FIND_DATA findData;
  LARGE_INTEGER size;
  hFind = FindFirstFile(dirNew, &findData);
  if (hFind == INVALID_HANDLE_VALUE) {
    cout << "Failed to find first file!\n";
    return;
  }
  // do
  //{
  //    // 忽略"."和".."两个结果
  //    if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName,
  //    "..") == 0 || strncmp(findData.cFileName, "cryptofile.", 11 ) == 0)
  //        continue;
  //    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)    //
  //    是否是目录
  //    {
  //        //cout << findData.cFileName << "\t<dir>\n";
  //    }
  //    else
  //    {
  //        size.LowPart = findData.nFileSizeLow;
  //        size.HighPart = findData.nFileSizeHigh;
  //        cout << findData.cFileName << "\t" << size.QuadPart << " bytes\t";
  //        if (index == 1) {
  //            string cipherHex = encrypt(findData.cFileName);
  //            //cout << "cipher : " << cipherHex << endl;
  //            writeCipher(cipherHex, findData.cFileName);
  //            cout << "\tencrypted!\n";
  //        }
  //        if (index == 2) {
  //            string plainHex = readCipher(findData.cFileName);
  //            //cout << "text : " << text1 << endl;
  //            writeCipher(plainHex, findData.cFileName);
  //            cout << "\tdecrypted!\n";
  //        }
  //    }
  //} while (FindNextFile(hFind, &findData));
  do {
    strcpy(dirNew, dir);
    strcat(dirNew, "\\");
    strcat(dirNew, findData.cFileName);
    // 是否是文件夹，并且名称不为"."或".."
    if (((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) &&
        (strcmp(findData.cFileName, ".") != 0) &&
        (strcmp(findData.cFileName, "..") != 0) &&
        (strcmp(findData.cFileName, "Release") != 0) &&
        (strcmp(findData.cFileName, ".vs") != 0) &&
        (strcmp(findData.cFileName, "Debug") != 0)) {
      // 将dirNew设置为搜索到的目录，并进行下一轮搜索

      cout << findData.cFileName << "--\n";
      findfile(index, dirNew);
    } else if (((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) &&
               (strncmp(findData.cFileName, "cryptofile.", 11) != 0)) {
      size.LowPart = findData.nFileSizeLow;
      size.HighPart = findData.nFileSizeHigh;
      cout << findData.cFileName << "\t" << size.QuadPart << " bytes\t";
      if (index == 1) {
        string cipherHex = encrypt(dirNew);
        // cout << "cipher : " << cipherHex << endl;
        writeCipher(cipherHex, dirNew);
        cout << "\tencrypted!\n";
      }
      if (index == 2) {
        string plainHex = readCipher(dirNew);
        // cout << "text : " << text1 << endl;
        writeCipher(plainHex, dirNew);
        cout << "\tdecrypted!\n";
      }
    }
  } while (FindNextFile(hFind, &findData));
  cout << "this dir all finished!\n";
  return;
}

int main() {
  // string filename = "crypto.txt";
  // string text = "hello WHU!";
  // cout << "text : " << text << endl;
  printf("gcc version ");
  printf("%d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
  int index;
  cout << "please input 1(encrypt) or 2(decrypt) " << endl;
  cin >> index;
  char password[20];
  cout << "please input password (you can set a password when encrypt for "
          "decrypt and cannot beyond 20)"
       << endl;
  cin >> password;
  initKV(password);
  char dir[100];
  _getcwd(dir, 100);
  findfile(index, dir);
  /*string cipherHex = encrypt(filename);
  cout << "cipher : " << cipherHex << endl;
  writeCipher(cipherHex, filename);
  string text1 = readCipher(filename);
  cout << "text : " << text1 << endl;*/
  system("pause");
  return 0;
}