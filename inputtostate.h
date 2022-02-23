//
//  inputtostate.h
//  fuzzer
//
//  Created by Alexandru Niculae on 1/30/22.
//

#pragma once

#include <bitset>

class Encoder {
public:
  virtual ~Encoder() { }
  virtual std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) = 0;
  
  std::vector<uint8_t> AdjustBytes(std::vector<uint8_t> bytes, I2SRecord *i2s_record);
  
  std::vector<uint8_t> Encode(std::vector<uint8_t> bytes, I2SRecord *i2s_record) {
    bytes = AdjustBytes(Encode(bytes), i2s_record);
    return bytes;
  }
};

class ZextEncoder : public Encoder {
public:
  ZextEncoder(int n_bytes) {
    this->n_bytes = n_bytes;
  }
  
  std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) override;
  
//private:
  int n_bytes;
};

class I2SMutation {
public:
  I2SMutation(size_t from, std::vector<uint8_t> bytes, std::vector<uint8_t> bytes_col) {
    this->from = from;
    this->bytes = bytes;
    this->bytes_col = bytes_col;
  }
  
  size_t from;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> bytes_col;
  
  void PrettyPrint() {
    if (from < 16) {
      printf("pos: %d ", from);
      printf("data: ");
      for (auto &byte : bytes) {
        printf("0x%02hhx ", byte);
      }

      printf("\n");
      
      printf("data col: ");
      for (auto &byte : bytes_col) {
        printf("0x%02hhx ", byte);
      }

      printf("\n");
    }
  }
};
