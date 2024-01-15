//
//  colorizer.h
//  fuzzerlib
//
//  Created by Alexandru Niculae on 1/14/22.
//

#pragma once

#include "range.h"
#include "sample.h"
#include <queue>
#include <vector>

class ColorizerContext {
public:
  virtual ~ColorizerContext() { }
};

class Colorizer {
public:
  virtual ColorizerContext* CreateContext(Sample* sample) { return NULL; };
  // should return 0 when colorizing done
  virtual int ColorizeStep(Sample* sample, ColorizerContext *context) { return 0; };
  virtual void ReportSuccess(Sample* sample, ColorizerContext* context) { };
  virtual void ReportFail(Sample* sample, ColorizerContext* context) { };
};

#define COLORIZE_STEP_INITIAL 16

class SimpleColorizerContext : public ColorizerContext {
public:
  SimpleColorizerContext() {}
  std::priority_queue<SampleRange> ranges;
};

class SimpleColorizer : public Colorizer {
public:
  virtual ColorizerContext* CreateContext(Sample* sample);
  virtual int ColorizeStep(Sample* sample, ColorizerContext* context);
  virtual void ReportSuccess(Sample* sample, ColorizerContext* context);
  virtual void ReportFail(Sample* sample, ColorizerContext* context);
};
