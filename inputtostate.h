//
//  inputtostate.h
//  fuzzer
//
//  Created by Alexandru Niculae on 1/30/22.
//

#pragma once

class Encoder {
public:
  virtual ~Encoder() { }
  virtual std::vector<uint8_t> Encode(std::vector<uint8_t> bytes) = 0;
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
