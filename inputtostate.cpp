//
//  inputtostate.cpp
//  fuzzerlib
//
//  Created by Alexandru Niculae on 1/30/22.
//

#include "common.h"
#include "mutator.h"
#include "inputtostate.h"

InputToStateMutator::InputToStateMutator(Fuzzer::ThreadContext *tc) {
  this->tc = tc;
  encoders = {
    new ZextEncoder(8),
    new ZextEncoder(4),
    new ZextEncoder(2),
    new ZextEncoder(1)
  };
}

uint64_t InputToStateMutator::GetI2SCode(I2SRecord *records) {
  uint64_t code = ((uint64_t)records->bb_offset << 32) + ((records->cmp_offset << 8) & 0xFFFFFFFFUL);
  return code;
}

bool InputToStateMutator::Mutate(Sample *inout_sample, Sample *colorized_sample, PRNG *prng,
                                 std::vector<Sample *> &all_samples) {
//  printf("before %d\n", inout_sample->size);
//  printf("\n\n");
//  printf("======================== I2S Mutate BEGIN ========================\n");
//
//  printf("----- RunSampleWithI2SInstrumentation -----\n");
  std::vector<I2SRecord*> i2s_records = RunSampleWithI2SInstrumentation(inout_sample);
  
//  printf("----- RunSampleWithI2SInstrumentation -----\n");
  std::vector<I2SRecord*> colorized_i2s_records = RunSampleWithI2SInstrumentation(colorized_sample);
  
//  printf("----- Candidate Records -----\n");
  std::vector<I2SRecord*> candidate_records = GetCandidateRecords(colorized_sample, i2s_records, colorized_i2s_records);
//  for (auto &record : candidate_records) {
//    printf("<-- Record -->\n");
//    for (int op_index = 0; op_index < 2; ++op_index) {
//      printf("Operand index %d: ", op_index);
//      for (int byte_index = 0; byte_index < record->op_length; ++byte_index) {
//        printf("0x%02hhx ", record->op_val[op_index][byte_index]);
//      }
//      printf("\n");
//    }
//  }
  
  
//  printf("----- Fixing Input -----\n");
  for (auto *record : candidate_records) {
    for (auto &encoder : encoders) {
      std::vector<uint8_t> encoded_pattern = encoder->Encode(record->op_val[0]);
      std::vector<uint8_t> encoded_mutation = encoder->Encode(record->op_val[1]);
      std::vector<size_t> matching_positions = GetMatchingPositions(colorized_sample, encoded_pattern);
      if (matching_positions.size() > 0) {
        
//        printf("--> Putting: ");
//        for (int i = 0; i < encoded_mutation.size(); ++i) {
//          printf("0x%02hhx ", encoded_mutation[i]);
//        }
//
//        printf("at ");
        
        for (auto &position : matching_positions) {
//          printf("%zd ", position);
          inout_sample->Replace(position, position + encoded_pattern.size(), (char *)encoded_mutation.data());
        }
        
//        printf("\n");
        
        break;
      }
    }
  }
  
  for (auto &record : i2s_records) {
    delete record;
  }
  
  for (auto &record : colorized_i2s_records) {
    delete record;
  }
  
//  *inout_sample = *colorized_sample;
  
//  printf("======================== I2S Mutate END ========================\n");
//  printf("\n\n");
  
  return true;
}

std::vector<I2SRecord*> InputToStateMutator::RunSampleWithI2SInstrumentation(Sample *inout_sample) {
  if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
    WARN("Error delivering sample, retrying with a clean target");
    tc->instrumentation->CleanTarget();
    if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
      FATAL("Repeatedly failed to deliver sample");
    }
  }
  
  RunResult result = tc->instrumentation->RunWithI2SInstrumentation(tc->target_argc, tc->target_argv, tc->fuzzer->init_timeout, tc->fuzzer->timeout);
  if (result != OK) {
    FATAL("RunWithI2SInstrumentation returned %d\n", result);
  }
  
  std::vector<I2SRecord*> i2s_records = tc->instrumentation->GetI2SRecords(true);
  
//  printf("Collected I2S Mappings\n");
//  printf("----------------------\n");
//  printf("%d\n", i2s_records.size());
//  for (auto &record : i2s_records) {
//    printf("<-- Record -->\n");
//    for (int op_index = 0; op_index < 2; ++op_index) {
//      printf("Operand index %d: ", op_index);
//      for (int byte_index = 0; byte_index < record->op_length; ++byte_index) {
//        printf("0x%02hhx ", record->op_val[op_index][byte_index]);
//      }
//      printf("\n");
//    }
//  }
  
  return i2s_records;
}

std::vector<I2SRecord*> InputToStateMutator::GetCandidateRecords(Sample *inout_sample,
                                                                 std::vector<I2SRecord*> i2s_records,
                                                                 std::vector<I2SRecord*> colorized_i2s_records) {
  std::unordered_map<uint64_t, I2SRecord*> code_to_record;
  
  for (auto &record: i2s_records) {
    code_to_record[GetI2SCode(record)] = record;
  }
  
  std::vector<I2SRecord*> candidate_records;
  for (auto &colorized_record: colorized_i2s_records) {
    I2SRecord *record = (code_to_record.count(GetI2SCode(colorized_record)) > 0) ? code_to_record[GetI2SCode(colorized_record)] : NULL;
    if (record == NULL) {
      continue;
    }
    
    if (record->op_val[0] == colorized_record->op_val[0]
        && record->op_val[1] == colorized_record->op_val[1]) {
      continue;
    }
    
    if (record->op_val[1] != colorized_record->op_val[1]) {
      colorized_record->op_val[0].swap(colorized_record->op_val[1]);
    }
    
    for (auto &encoder : encoders) {
      std::vector<size_t> matching_positions = GetMatchingPositions(inout_sample, encoder->Encode(colorized_record->op_val[0]));
      if (matching_positions.size() > 0) {
        candidate_records.push_back(colorized_record);
        break;
      }
    }
  }
  
  return candidate_records;
}

bool InputToStateMutator::Match(uint8_t *sample, uint8_t *pattern, int size) {
  for (int i = 0; i < size; ++i) {
    if (sample[i] != pattern[i]) {
      return false;
    }
  }
  
  return true;
}

//TO DO: Implement KMP
std::vector<size_t> InputToStateMutator::GetMatchingPositions(Sample *inout_sample, std::vector<uint8_t> pattern) {
  std::vector<size_t> matching_positions;
  for (size_t i = 0; i + pattern.size() <= inout_sample->size; ++i) {
    if (Match((uint8_t *)(inout_sample->bytes + i), pattern.data(), pattern.size())) {
      matching_positions.push_back(i);
    }
  }
  
  return matching_positions;
}

std::vector<uint8_t> ZextEncoder::Encode(std::vector<uint8_t> bytes) {
  while (bytes.size() > n_bytes) {
    bytes.pop_back();
  }
  
  while (bytes.size() < n_bytes) {
    bytes.push_back(0x0);
  }
  
  return bytes;
}


