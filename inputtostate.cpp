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
    new ZextEncoder(8, false), new ZextEncoder(8, true),
    new ZextEncoder(4, false), new ZextEncoder(4, true),
    new ZextEncoder(2, false), new ZextEncoder(2, true),
    new ZextEncoder(1, false), new ZextEncoder(1, true),
    new SextEncoder(8, false), new SextEncoder(8, true),
    new SextEncoder(4, false), new SextEncoder(4, true),
    new SextEncoder(2, false), new SextEncoder(2, true),
    new SextEncoder(1, false), new SextEncoder(1, true),
  };
}

uint64_t InputToStateMutator::GetI2SCode(I2SRecord *records) {
  uint64_t code = ((uint64_t)records->bb_offset << 32) + ((records->cmp_offset << 8) & 0xFFFFFFFFUL);
  return code;
}

//void InputToStateMutator::UpdateI2SBranchInfo(std::vector<I2SData> i2s_data_vector) {
//  for (auto &i2s_data : i2s_data_vector) {
//    size_t i2s_address = i2s_data.bb_address + i2s_data.bb_offset;
//    if (i2s_records_info.count(i2s_address) == 0) {
//      i2s_records_info[i2s_address] = (I2SRecordInfo*)malloc(sizeof(I2SRecordInfo));
//    }
//
//    i2s_records_info[i2s_address]->hit_branches |= (1 << i2s_data.BranchPath());
//  }
//}

void InputToStateMutator::Fix(Sample *inout_sample, size_t opt_address) {
  std::pair<RunResult, std::vector<I2SData>> i2s_run_pair = RunSampleWithI2SInstrumentation(inout_sample);
  if (i2s_run_pair.first != OK) {
    return;
  }
  std::vector<I2SData> i2s_data_vector = i2s_run_pair.second;
  
  std::vector<I2SMutation> i2s_mutations;
  for (auto &i2s_data: i2s_data_vector) {
    if (i2s_data.i2s_record->bb_address + i2s_data.i2s_record->cmp_offset != 0x100005e75) {
      continue;
    }
    
    
//    i2s_data.PrettyPrint();
//    colorized_i2s_data.PrettyPrint();
    
    for (int i = 0; i < 2; i++, i2s_data.op_val[0].swap(i2s_data.op_val[1])) {
      for (auto &encoder : encoders) {
//        if (!encoder->IsApplicable(record) || !encoder->IsApplicable(colorized_record)) {
//          continue;
//        }
        
        if (encoder->Encode(i2s_data.op_val[0]).size() != 4) {
          continue;
        }
        
        if (encoder->Encode(i2s_data.op_val[0]) == encoder->Encode(i2s_data.op_val[1], i2s_data)) {
          continue;
        }
        
        std::vector<size_t> matching_positions = GetMatchingPositions(inout_sample, encoder->Encode(i2s_data.op_val[0]));
        
        // !!!! Pay attention here.
        for (auto &pos : matching_positions) {
          if (pos > 53) {
            break;
          }
          if (pos != 29 && pos != 53) {
            continue;
          }
          i2s_mutations.push_back(
                I2SMutation(pos,
                            encoder->Encode(i2s_data.op_val[1], i2s_data),
                            std::vector<uint8_t>(),
                            i2s_data.i2s_record));
        }
      }
    }
  }
  
//  printf("----- :D Mutations -----\n");
//  for (auto &mutation : i2s_mutations) {
//    mutation.PrettyPrint();
//  }
//  printf("\n\n");
  
  for (auto &mutation : i2s_mutations) {
    inout_sample->Replace(mutation.from, mutation.from + mutation.bytes.size(), (char *)mutation.bytes.data());
  }
}

bool InputToStateMutator::Mutate(Sample *inout_sample, Sample *colorized_sample, PRNG *prng,
                                 std::vector<Sample *> &all_samples) {

//  printf("======================== I2S Mutate BEGIN ========================\n");
//  inout_sample->PrettyPrint("inout");
//  colorized_sample->PrettyPrint("col");

  std::pair<RunResult, std::vector<I2SData>> i2s_run_pair = RunSampleWithI2SInstrumentation(inout_sample);
  if (i2s_run_pair.first != OK) {
    return false;
  }
  std::vector<I2SData> i2s_data_vector = i2s_run_pair.second;

  i2s_run_pair = RunSampleWithI2SInstrumentation(colorized_sample);
  if (i2s_run_pair.first != OK) {
    *inout_sample = *colorized_sample;
    return false;
  }
  std::vector<I2SData> colorized_i2s_data_vector = i2s_run_pair.second;
  
//  UpdateI2SBranchInfo(i2s_records);
  
//  I2SRecord
  
  
  std::vector<I2SMutation> i2s_mutations = GetMutations(inout_sample, colorized_sample, i2s_data_vector, colorized_i2s_data_vector);
  
//  printf("----- Mutations -----\n");
//  for (auto &mutation : i2s_mutations) {
//    mutation.PrettyPrint();
//  }
//  printf("\n\n");
  
  for (auto &mutation : i2s_mutations) {
    inout_sample->Replace(mutation.from, mutation.from + mutation.bytes.size(), (char *)mutation.bytes.data());
    colorized_sample->Replace(mutation.from, mutation.from + mutation.bytes_col.size(), (char *)mutation.bytes_col.data());
  }

//  printf("======================== I2S Mutate END ========================\n");
  
  return true;
}

std::pair<RunResult, std::vector<I2SData>> InputToStateMutator::RunSampleWithI2SInstrumentation(Sample *inout_sample) {
  if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
    WARN("Error delivering sample, retrying with a clean target");
    tc->instrumentation->CleanTarget();
    if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
      FATAL("Repeatedly failed to deliver sample");
    }
  }
  
  RunResult result = tc->instrumentation->RunWithI2SInstrumentation(tc->target_argc, tc->target_argv, tc->fuzzer->init_timeout, tc->fuzzer->timeout);
  if (result != OK) {
    return {result, std::vector<I2SData>()};
  }
  
  std::vector<I2SData> i2s_data_vector = tc->instrumentation->GetI2SData(true);
  
  return {result, i2s_data_vector};
}

std::vector<I2SMutation> InputToStateMutator::GetMutations(Sample *inout_sample,
                                                           Sample *colorized_sample,
                                                                 std::vector<I2SData> i2s_data_vector,
                                                                 std::vector<I2SData> colorized_i2s_data_vector) {
//  printf("getmutations sizes %d %d\n", i2s_data_vector.size(), colorized_i2s_data_vector.size());
  std::unordered_map<uint64_t, I2SData> code_to_i2s_data;
  
  for (auto &i2s_data: i2s_data_vector) {
    code_to_i2s_data[GetI2SCode(i2s_data.i2s_record)] = i2s_data;
  }
  
//  colorized_sample->PrettyPrint("col");
  
  std::vector<I2SMutation> i2s_mutations;
  
  std::reverse(colorized_i2s_data_vector.begin(), colorized_i2s_data_vector.end());
  for (auto &colorized_i2s_data: colorized_i2s_data_vector) {
    if (code_to_i2s_data.count(GetI2SCode(colorized_i2s_data.i2s_record)) == 0) {
      continue;
    }
    I2SData i2s_data = code_to_i2s_data[GetI2SCode(colorized_i2s_data.i2s_record)];
    
    if (i2s_data.op_val[0] == colorized_i2s_data.op_val[0]
        && i2s_data.op_val[1] == colorized_i2s_data.op_val[1]) {
      continue;
    }
    
//    i2s_data.PrettyPrint();
//    colorized_i2s_data.PrettyPrint();
    
    for (int i = 0; i < 2; i++, colorized_i2s_data.op_val[0].swap(colorized_i2s_data.op_val[1]),
        i2s_data.op_val[0].swap(i2s_data.op_val[1])) {
      
      if (i2s_data.op_val[0] == colorized_i2s_data.op_val[0]) {
        continue;
      }
      
      for (auto &encoder : encoders) {
//        if (!encoder->IsApplicable(record) || !encoder->IsApplicable(colorized_record)) {
//          continue;
//        }
        
        if (encoder->Encode(i2s_data.op_val[0]) == encoder->Encode(i2s_data.op_val[1], i2s_data)) {
          continue;
        }
        
        std::vector<size_t> matching_positions = GetMatchingPositions(inout_sample, encoder->Encode(i2s_data.op_val[0]));
        
        std::vector<size_t> matching_positions_col = GetMatchingPositions(colorized_sample, encoder->Encode(colorized_i2s_data.op_val[0]));
        
        std::vector<size_t> common_positions;
        std::set_intersection(matching_positions.begin(),matching_positions.end(),
                              matching_positions_col.begin(),matching_positions_col.end(),
                              back_inserter(common_positions));
        
        
        // !!!! Pay attention here.
        for (auto &pos : common_positions) {
          i2s_mutations.push_back(
                I2SMutation(pos,
                            encoder->Encode(i2s_data.op_val[1], i2s_data),
                            encoder->Encode(colorized_i2s_data.op_val[1], colorized_i2s_data),
                            i2s_data.i2s_record));
        }
      }
    }
    
    if (i2s_mutations.size() > 0) {
      return i2s_mutations;
    }
  }
  
  return i2s_mutations;
}

bool InputToStateMutator::Match(uint8_t *sample, uint8_t *pattern, int size) {
  for (int i = 0; i < size; ++i) {
    if (sample[i] != pattern[i]) {
      return false;
    }
  }
  
  return true;
}

// TO DO: Implement KMP
std::vector<size_t> InputToStateMutator::GetMatchingPositions(Sample *inout_sample, std::vector<uint8_t> pattern) {
  std::vector<size_t> matching_positions;
  for (size_t i = 0; i + pattern.size() <= inout_sample->size; ++i) {
    if (Match((uint8_t *)(inout_sample->bytes + i), pattern.data(), pattern.size())) {
      matching_positions.push_back(i);
    }
  }
  
  return matching_positions;
}

bool ZextEncoder::IsApplicable(std::vector<uint8_t> bytes) {
  if (bytes.size() < n_bytes) {
    return false;
  }
  
  for (int i = n_bytes; i < bytes.size(); ++i) {
    if (bytes[i] != 0x00) {
      return false;
    }
  }
  
  return true;
}

std::vector<uint8_t> ZextEncoder::Encode(std::vector<uint8_t> bytes) {
  while (bytes.size() > n_bytes) {
    bytes.pop_back();
  }
  
  bytes = Encoder::Encode(bytes);
  return bytes;
}

bool SextEncoder::IsApplicable(std::vector<uint8_t> bytes) {
  if (bytes.size() < n_bytes) {
    return false;
  }
  
  uint8_t sign = (bytes[n_bytes-1] & 0x80) >> 7;
  for (int i = n_bytes; i < bytes.size(); ++i) {
    if (!sign && bytes[i] != 0x00) {
      return false;
    }
    
    if (sign && bytes[i] != 0xff) {
      return false;
    }
  }
  
  return true;
}

std::vector<uint8_t> SextEncoder::Encode(std::vector<uint8_t> bytes) {
  while (bytes.size() > n_bytes) {
    bytes.pop_back();
  }
  
  bytes = Encoder::Encode(bytes);
  return bytes;
}

std::vector<uint8_t> Encoder::AdjustBytes(std::vector<uint8_t> bytes, I2SData i2s_data) {
  if (bytes.size() == 0) {
    return bytes;
  }
  
  int adjust;
  switch (i2s_data.i2s_record->type) {
    case CMPB:
    case CMPL:
//      printf("CMPB CMPL\n");
      adjust = -1;
      break;
      
    case CMPA:
    case CMPG:
//      printf("CMPA CMPG\n");
      adjust = 1;
      break;
      
    default:
//      printf("plm\n");
      adjust = 0;
  }
  
//  if (ShouldTakeReversedPath(i2s_record)) {
////    printf("aha\n");
//    adjust *= -1;
//  }

  
//  if (adjust != 0) {
//    printf("ADJUST %d\n", adjust);
//  }
  
  // TO DO: correct here
  bytes[0] += (1 - 2 * prng->Rand(0, 1)) * adjust;
  return bytes;
}

