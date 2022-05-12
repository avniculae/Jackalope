//
//  inputtostate.h
//  fuzzer
//
//  Created by Alexandru Niculae on 1/30/22.
//

#pragma once

#include <bitset>
#include <mersenne.h>

class Encoder {
public:
  Encoder() : prng(new MTPRNG()) { }
  virtual std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) = 0;
  virtual bool IsApplicable(std::vector<uint8_t> bytes) = 0;
  
  bool IsApplicable(I2SData i2s_data) {
    return IsApplicable(i2s_data.op_val[0]) && IsApplicable(i2s_data.op_val[1]);
  }
  
  std::vector<uint8_t> AdjustBytes(std::vector<uint8_t> bytes, I2SData i2s_data);
  
  std::vector<uint8_t> Encode(std::vector<uint8_t> bytes, I2SData i2s_data) {
    bytes = AdjustBytes(Encode(bytes), i2s_data);
    return bytes;
  }
  
  PRNG *prng;
};

class ZextEncoder : public Encoder {
public:
  ZextEncoder(int n_bytes) {
    this->n_bytes = n_bytes;
  }
  
  std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) override;
  bool IsApplicable(std::vector<uint8_t> bytes) override;
  
//private:
  int n_bytes;
};

class SextEncoder : public Encoder {
public:
  SextEncoder(int n_bytes) {
    this->n_bytes = n_bytes;
  }
  
  std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) override;
  bool IsApplicable(std::vector<uint8_t> bytes) override;
  
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
