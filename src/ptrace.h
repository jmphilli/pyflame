// Copyright 2016 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include <memory>
#include <string>

namespace pyflame {

class PtraceCtx {
 public:
  PtraceCtx(pid_t pid);
  ~PtraceCtx();

  // get regs from a process
  void GetRegs(user_regs_struct *regs);

  // set regs for the process
  void SetRegs(user_regs_struct *regs);

  void Poke(unsigned long addr, long data);

  long Peek(unsigned long addr);

  void Cont();

  void SingleStep();

  std::string PeekString(unsigned long addr);

  std::unique_ptr<uint8_t[]> PeekBytes(unsigned long addr, size_t nbytes);

  // call a function pointer
  long PtraceCallFunction(unsigned long addr);

 private:
  pid_t pid_;
  unsigned long probe_;

  unsigned long AllocPage();
  void DeallocPage();

  std::vector<pid_t> ListThreads();

  void PauseChildThreads();
  void ResumeChildThreads();
};
}  // namespace pyflame
