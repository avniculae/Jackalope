/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

class Range {
public:
  size_t from;
  size_t to;

  bool operator<(const Range& other) const {
    return this->from < other.from;
  }
};

class SampleRange : public Range {
public:
  SampleRange() { }

  SampleRange(size_t from, size_t to) {
    this->from = from;
    this->to = to;
  }
  
  size_t length() {
    return to - from;
  }
  
  bool operator<(const SampleRange& other) const {
    if (((SampleRange*)this)->length() == ((SampleRange)other).length()) {
      return from < other.from;
    }
    
    return ((SampleRange*)this)->length() < ((SampleRange)other).length();
  }
};



