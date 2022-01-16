//
//  colorizer.cpp
//  fuzzerlib
//
//  Created by Alexandru Niculae on 1/14/22.
//

#include "common.h"
#include "colorizer.h"
 
ColorizerContext* SimpleColorizer::CreateContext(Sample* sample) {
  SimpleColorizerContext *context = new SimpleColorizerContext();
  
  context->ranges.push(SampleRange(0, sample->size));
  
  return context;
}

int SimpleColorizer::ColorizeStep(Sample* sample, ColorizerContext* context) {
  SimpleColorizerContext* colorizer_context = (SimpleColorizerContext*)context;
  if (colorizer_context->ranges.size() == 0) {
    return 0;
  }
  
  SampleRange longest_range = colorizer_context->ranges.top();
  if (longest_range.length() <= 1) {
    return 0;
  }
  
  sample->Randomize(longest_range.from, longest_range.to);
  
//  printf("Sample info:  %p %zx\n", sample->bytes, sample->size);
//  printf("Longest range: %zx %zx\n", longest_range.from, longest_range.to);
//  printf("%zu\n", colorizer_context->ranges.size());
//  printf("            \n");
  
  return 1;
}

void SimpleColorizer::ReportSuccess(Sample* sample, ColorizerContext* context) {
  SimpleColorizerContext* colorizer_context = (SimpleColorizerContext*)context;
  
  Range longest_range = colorizer_context->ranges.top();
//  printf("Success Longest range: %zx %zx\n", longest_range.from, longest_range.to);
//  printf("%zu\n", colorizer_context->ranges.size());
//  printf("            \n");
  
  colorizer_context->ranges.pop();
}

void SimpleColorizer::ReportFail(Sample* sample, ColorizerContext* context) {
  SimpleColorizerContext* colorizer_context = (SimpleColorizerContext*)context;
  SampleRange longest_range = colorizer_context->ranges.top();
  size_t mid = longest_range.from + (longest_range.to - longest_range.from) / 2;
  colorizer_context->ranges.pop();
  colorizer_context->ranges.push(SampleRange(longest_range.from, mid));
  colorizer_context->ranges.push(SampleRange(mid, longest_range.to));
  
  //  printf("Longest mid range: %zx %zx %zx\n", longest_range.from, mid, longest_range.to);
  //  printf("            \n");
}
