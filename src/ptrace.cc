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

#include "./ptrace.h"

#include <dirent.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "./exc.h"

namespace pyflame {

static long syscall_code = 0x050f;  // syscall

void PtraceCtx::PtraceCtx(pid_t pid) : pid_(pid), probe_(0) {
  std::ostringstream ss;
  if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
    ss << "Failed to attach to PID " << pid << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
  if (wait(nullptr) == -1) {
    ss << "Failed to wait on PID " << pid << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtraceCtx::~PtraceCtx() {
  if (ptrace(PTRACE_DETACH, pid_, 0, 0)) {
    std::ostringstream ss;
    ss << "Failed to detach PID " << pid_ << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtraceCtx::GetRegs(user_regs_struct *regs) {
  if (ptrace(PTRACE_GETREGS, pid_, 0, regs)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_GETREGS: " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtraceCtx::SetRegs(struct user_regs_struct *regs) {
  if (ptrace(PTRACE_SETREGS, pid_, 0, regs)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_SETREGS: " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtraceCtx::Poke(unsigned long addr, long data) {
  if (ptrace(PTRACE_POKEDATA, pid_, addr, (void *)data)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_POKEDATA at " << reinterpret_cast<void *>(addr)
       << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

long PtraceCtx::Peek(unsigned long addr) {
  errno = 0;
  const long data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  if (data == -1 && errno != 0) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_PEEKDATA at " << reinterpret_cast<void *>(addr)
       << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
  return data;
}

static void do_wait() {
  int status;
  if (wait(&status) == -1) {
    throw PtraceException("Failed to PTRACE_CONT");
  }
  if (WIFSTOPPED(status)) {
    if (WSTOPSIG(status) != SIGTRAP) {
      std::ostringstream ss;
      ss << "Failed to PTRACE_CONT - unexpectedly got status  "
         << strsignal(status);
      throw PtraceException(ss.str());
    }
  } else {
    std::ostringstream ss;
    ss << "Failed to PTRACE_CONT - unexpectedly got status  " << status;
    throw PtraceException(ss.str());
  }
}

void PtraceCtx::Cont() {
  ptrace(PTRACE_CONT, pid_, 0, 0);
  do_wait();
}

void PtraceCtx::SingleStep() {
  ptrace(PTRACE_SINGLESTEP, pid_, 0, 0);
  do_wait();
}

std::string PtracePeekString(unsigned long addr) {
  std::ostringstream dump;
  unsigned long off = 0;
  while (true) {
    const long val = Peek(addr + off);

    // XXX: this can be micro-optimized, c.f.
    // https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
    const std::string chunk(reinterpret_cast<const char *>(&val), sizeof(val));
    dump << chunk.c_str();
    if (chunk.find_first_of('\0') != std::string::npos) {
      break;
    }
    off += sizeof(val);
  }
  return dump.str();
}

std::unique_ptr<uint8_t[]> PtraceCtx::PeekBytes(unsigned long addr,
                                                size_t nbytes) {
  // align the buffer to a word size
  if (nbytes % sizeof(long)) {
    nbytes = (nbytes / sizeof(long) + 1) * sizeof(long);
  }
  std::unique_ptr<uint8_t[]> bytes(new uint8_t[nbytes]);

  size_t off = 0;
  while (off < nbytes) {
    const long val = PtracePeek(pid, addr + off);
    memmove(bytes.get() + off, &val, sizeof(val));
    off += sizeof(val);
  }
  return bytes;
}

unsigned long PtraceCtx::AllocPage() {
  user_regs_struct oldregs = GetRegs();
  long orig_code = Peek(oldregs.rip);
  Poke(oldregs.rip, syscall_code);

  user_regs_struct newregs = oldregs;
  newregs.rax = SYS_mmap;
  newregs.rdi = 0;                                   // addr
  newregs.rsi = getpagesize();                       // len
  newregs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
  newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;         // flags
  newregs.r8 = -1;                                   // fd
  newregs.r9 = 0;                                    // offset
  SetRegs(&newregs);
  SingleStep();
  unsigned long result = GetRegs().rax;

  SetRegs(&oldregs);
  Poke(oldregs.rip, orig_code);

  return result;
}

void PtraceCtx::DeallocPage() {
  // TODO
}

std::vector<pid_t> PtraceCtx::ListThreads() {
  std::vector<pid_t> result;
  std::ostringstream dirname;
  dirname << "/proc/" << pid_ << "/task";
  DIR *dir = opendir(dirname.str().c_str());
  if (dir == nullptr) {
    throw PtraceException("Failed to list threads");
  }
  dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    std::string name = entry->d_name;
    if (name != "." && name != "..") {
      result.push_back(static_cast<pid_t>(std::stoi(name)));
    }
  }
  return result;
}

void PtraceCtx::PauseChildThreads() {
  for (auto tid : ListThreads(pid_)) {
    if (tid != pid_) PtraceAttach(tid);
  }
}

void PtraceCtx::ResumeChildThreads() {
  for (auto tid : ListThreads(pid_)) {
    if (tid != pid_) PtraceDetach(tid);
  }
}

long PtraceCtx::CallFunction(unsigned long addr) {
  if (probe_ == 0) {
    PauseChildThreads();
    probe_ = AllocPage();
    ResumeChildThreads();
    if (probe_ == (unsigned long)MAP_FAILED) {
      return -1;
    }

    // std::cerr << "probe point is at " << reinterpret_cast<void *>(probe_)
    //           << "\n";
    long code = 0;
    uint8_t *new_code_bytes = (uint8_t *)&code;
    new_code_bytes[0] = 0xff;  // CALL
    new_code_bytes[1] = 0xd0;  // rax
    new_code_bytes[2] = 0xcc;  // TRAP
    Poke(probe_, code);
  }

  user_regs_struct oldregs = GetRegs();
  user_regs_struct newregs = oldregs;
  newregs.rax = addr;
  newregs.rip = probe_;

  SetRegs(newregs);
  Cont();

  newregs = GetRegs();
  SetRegs(oldregs);
  return newregs.rax;
};
#endif
}  // namespace pyflame
