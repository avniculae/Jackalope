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

void InputToStateMutator::UpdateI2SBranchInfo(std::vector<I2SRecord*> i2s_records) {
  for (auto &i2s_record : i2s_records) {
    size_t i2s_address = i2s_record->bb_address + i2s_record->bb_offset;
    if (i2s_records_info.count(i2s_address) == 0) {
      i2s_records_info[i2s_address] = (I2SRecordInfo*)malloc(sizeof(I2SRecordInfo));
    }
    
    i2s_records_info[i2s_address]->hit_branches |= (1 << i2s_record->BranchPath());
  }
}

bool InputToStateMutator::Mutate(Sample *inout_sample, Sample *colorized_sample, PRNG *prng,
                                 std::vector<Sample *> &all_samples) {

  printf("======================== I2S Mutate BEGIN ========================\n");
  inout_sample->PrettyPrint("inout");
  colorized_sample->PrettyPrint("col");

  std::pair<RunResult, std::vector<I2SRecord*>> i2s_run_pair = RunSampleWithI2SInstrumentation(inout_sample);
  if (i2s_run_pair.first != OK) {
    return false;
  }
  std::vector<I2SRecord*> i2s_records = i2s_run_pair.second;

  i2s_run_pair = RunSampleWithI2SInstrumentation(colorized_sample);
  if (i2s_run_pair.first != OK) {
    *inout_sample = *colorized_sample;
    return false;
  }
  std::vector<I2SRecord*> colorized_i2s_records = i2s_run_pair.second;
  
  UpdateI2SBranchInfo(i2s_records);
  
  std::vector<I2SMutation> i2s_mutations = GetMutations(inout_sample, colorized_sample, i2s_records, colorized_i2s_records);
  
  printf("----- Mutations -----\n");
  for (auto &mutation : i2s_mutations) {
    mutation.PrettyPrint();
  }
  printf("\n\n");
  
  for (auto &mutation : i2s_mutations) {
    inout_sample->Replace(mutation.from, mutation.from + mutation.bytes.size(), (char *)mutation.bytes.data());
    colorized_sample->Replace(mutation.from, mutation.from + mutation.bytes_col.size(), (char *)mutation.bytes_col.data());
  }
  
  for (auto &record : i2s_records) {
    delete record;
  }
  
  for (auto &record : colorized_i2s_records) {
    delete record;
  }
  
  printf("======================== I2S Mutate END ========================\n");
  
  return true;
}

std::pair<RunResult, std::vector<I2SRecord*>> InputToStateMutator::RunSampleWithI2SInstrumentation(Sample *inout_sample) {
  if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
    WARN("Error delivering sample, retrying with a clean target");
    tc->instrumentation->CleanTarget();
    if (!tc->sampleDelivery->DeliverSample(inout_sample)) {
      FATAL("Repeatedly failed to deliver sample");
    }
  }
  
  RunResult result = tc->instrumentation->RunWithI2SInstrumentation(tc->target_argc, tc->target_argv, tc->fuzzer->init_timeout, tc->fuzzer->timeout);
  if (result != OK) {
    return {result, std::vector<I2SRecord*>()};
  }
  
  std::vector<I2SRecord*> i2s_records = tc->instrumentation->GetI2SRecords(true);
  
  return {result, i2s_records};
}

std::vector<I2SMutation> InputToStateMutator::GetMutations(Sample *inout_sample,
                                                           Sample *colorized_sample,
                                                                 std::vector<I2SRecord*> i2s_records,
                                                                 std::vector<I2SRecord*> colorized_i2s_records) {
  std::unordered_map<uint64_t, I2SRecord*> code_to_record;
  
  for (auto &record: i2s_records) {
    code_to_record[GetI2SCode(record)] = record;
  }
  
  colorized_sample->PrettyPrint("col");
  
  std::vector<I2SMutation> i2s_mutations;
  
  std::reverse(colorized_i2s_records.begin(), colorized_i2s_records.end());
  for (auto &colorized_record: colorized_i2s_records) {
    I2SRecord *record = (code_to_record.count(GetI2SCode(colorized_record)) > 0) ? code_to_record[GetI2SCode(colorized_record)] : NULL;
    if (record == NULL) {
      continue;
    }
    
    if (record->op_val[0] == colorized_record->op_val[0]
        && record->op_val[1] == colorized_record->op_val[1]) {
      continue;
    }
    
    record->PrettyPrint();
    colorized_record->PrettyPrint();
    
    for (int i = 0; i < 2; i++, colorized_record->op_val[0].swap(colorized_record->op_val[1]),
        record->op_val[0].swap(record->op_val[1])) {
      
      if (record->op_val[0] == colorized_record->op_val[0]) {
        continue;
      }
      
      for (auto &encoder : encoders) {
        if (encoder->Encode(record->op_val[0]) == encoder->Encode(record->op_val[1], record)) {
          continue;
        }
        
        std::vector<size_t> matching_positions = GetMatchingPositions(inout_sample, encoder->Encode(record->op_val[0]));
        
        std::vector<size_t> matching_positions_col = GetMatchingPositions(colorized_sample, encoder->Encode(colorized_record->op_val[0]));
        
        std::vector<size_t> common_positions;
        std::set_intersection(matching_positions.begin(),matching_positions.end(),
                              matching_positions_col.begin(),matching_positions_col.end(),
                              back_inserter(common_positions));
        
        
        // !!!! Pay attention here.
        for (auto &pos : common_positions) {
          i2s_mutations.push_back(
                I2SMutation(pos,
                            encoder->Encode(record->op_val[1], record),
                            encoder->Encode(colorized_record->op_val[1], colorized_record)));
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

std::vector<uint8_t> Encoder::AdjustBytes(std::vector<uint8_t> bytes, I2SRecord *i2s_record) {
  if (bytes.size() == 0) {
    return bytes;
  }
  
  int adjust;
  switch (i2s_record->type) {
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
  bytes[0] += adjust;
  return bytes;
}

