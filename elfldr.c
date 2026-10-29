/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/sched.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps4/kernel.h>
#include <ps4/klog.h>

#include "elfldr.h"
#include "log.h"
#include "pt.h"

/**
 * Convenient macros.
 **/
#define MB(x) (x * 0x100000)
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)                                                             \
  ((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0)           \
   | (((x) & PF_X) ? PROT_EXEC : 0))

/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t *elf;
  pid_t pid;

  intptr_t base_addr;
  size_t base_size;
  uintptr_t min_vaddr;
  void *base_mirror;
} elfldr_ctx_t;

/**
 * Parse a R_X86_64_RELATIVE relocatable.
 **/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela *rela) {
  intptr_t *loc;
  intptr_t val;

  if(rela->r_offset < ctx->min_vaddr || ctx->base_size < sizeof(*loc)
     || rela->r_offset - ctx->min_vaddr > ctx->base_size - sizeof(*loc)) {
    return -1;
  }

  loc = ctx->base_mirror + rela->r_offset - ctx->min_vaddr;
  val = ctx->base_addr - ctx->min_vaddr + rela->r_addend;

  *loc = val;

  return 0;
}

/**
 * Parse a PT_LOAD program header.
 **/
static int
data_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void *data;

  if(!phdr->p_memsz) {
    return 0;
  }

  if(!phdr->p_filesz) {
    return 0;
  }

  if(phdr->p_filesz > phdr->p_memsz || phdr->p_vaddr < ctx->min_vaddr
     || phdr->p_vaddr - ctx->min_vaddr > ctx->base_size
     || phdr->p_filesz > ctx->base_size - (phdr->p_vaddr - ctx->min_vaddr)) {
    return -1;
  }

  data = ctx->base_mirror + phdr->p_vaddr - ctx->min_vaddr;
  memcpy(data, ctx->elf + phdr->p_offset, phdr->p_filesz);

  return 0;
}

/**
 * Check that the range [off, off+len) lies inside a buffer of the given size.
 **/
static int
elfldr_in_bounds(uint64_t off, uint64_t len, size_t size) {
  return off <= size && len <= size - off;
}

/**
 * Ensure the data is a well-formed ELF, so that the program and section
 * headers, the segments, and the relocation tables can be read without
 * leaving the buffer.
 **/
int
elfldr_sanity_check(uint8_t *elf, size_t elf_size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;

  if(elf_size < sizeof(Elf64_Ehdr)) {
    return -1;
  }

  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
     || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F'
     || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    return -1;
  }

  if(ehdr->e_phnum) {
    if(ehdr->e_phentsize != sizeof(Elf64_Phdr)
       || !elfldr_in_bounds(ehdr->e_phoff,
                            (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr),
                            elf_size)) {
      return -1;
    }

    phdr = (Elf64_Phdr *)(elf + ehdr->e_phoff);
    for(int i = 0; i < ehdr->e_phnum; i++) {
      if(!elfldr_in_bounds(phdr[i].p_offset, phdr[i].p_filesz, elf_size)) {
        return -1;
      }

      if(phdr[i].p_type == PT_LOAD
         && (phdr[i].p_filesz > phdr[i].p_memsz
             || phdr[i].p_memsz > UINT64_MAX - phdr[i].p_vaddr)) {
        return -1;
      }
    }
  }

  if(ehdr->e_shnum) {
    if(ehdr->e_shentsize != sizeof(Elf64_Shdr)
       || !elfldr_in_bounds(ehdr->e_shoff,
                            (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr),
                            elf_size)) {
      return -1;
    }

    shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff);
    for(int i = 0; i < ehdr->e_shnum; i++) {
      if(shdr[i].sh_type == SHT_RELA
         && !elfldr_in_bounds(shdr[i].sh_offset, shdr[i].sh_size, elf_size)) {
        return -1;
      }
    }
  }

  return 0;
}

/**
 * Get the protection bits of a page, combining every segment that covers it.
 **/
static int
elfldr_page_protection(const Elf64_Phdr *phdr, unsigned count, uintptr_t page) {
  int prot = 0;

  for(unsigned i = 0; i < count; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    uintptr_t start = TRUNC_PG(phdr[i].p_vaddr);
    uintptr_t end = ROUND_PG(phdr[i].p_vaddr + phdr[i].p_memsz);

    if(page >= start && page < end) {
      prot |= PFLAGS(phdr[i].p_flags);
    }
  }

  return prot;
}

/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = { .elf = elf, .pid = pid };

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Compute size of virtual memory region.
  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  if(min_vaddr == (size_t)-1) {
    LOG_PUTS("elfldr_load: ELF has no loadable segments");
    return 0;
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;
  ctx.min_vaddr = min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    LOG_PUTS("elfldr_load: ELF type not supported");
    return 0;
  }

  if((ctx.base_mirror = mmap(NULL, ctx.base_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
     == MAP_FAILED) {
    LOG_PERROR("mmap");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr
      = pt_mmap(pid, ctx.base_addr, ctx.base_size, prot, flags, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    munmap(ctx.base_mirror, ctx.base_size);
    return 0;
  }

  // Parse program headers.
  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
      case PT_LOAD:
        error = data_load(&ctx, &phdr[i]);
        break;
    }
  }

  // Apply relocations.
  for(int i = 0; i < ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela *rela = (Elf64_Rela *)(elf + shdr[i].sh_offset);
    for(int j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela) && !error; j++) {
      switch(rela[j].r_info & 0xffffffffl) {
        case R_X86_64_RELATIVE:
          error = r_relative(&ctx, &rela[j]);
          break;
      }
    }
  }

  if(pt_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("pt_copyin");
    error = 1;
  }

  // Set protection bits on mapped pages, once for each run of equal pages.
  for(uintptr_t page = min_vaddr; page < max_vaddr && !error;) {
    int pbits = elfldr_page_protection(phdr, ehdr->e_phnum, page);
    uintptr_t end = page + PAGE_SIZE;

    while(end < max_vaddr
          && elfldr_page_protection(phdr, ehdr->e_phnum, end) == pbits) {
      end += PAGE_SIZE;
    }

    if(pt_mprotect(pid, ctx.base_addr + page - min_vaddr, end - page, pbits)) {
      LOG_PT_PERROR(pid, "pt_mprotect");
      error = 1;
    }

    page = end;
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    LOG_PT_PERROR(pid, "pt_msync");
    error = 1;
  }

  munmap(ctx.base_mirror, ctx.base_size);

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry - min_vaddr;
}

/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  intptr_t entry;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    return -1;
  }

  if(!(entry = elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    return -1;
  }

  r.r_rsp &= ~0xfl;
  r.r_rsp -= 8;
  r.r_rip = entry;

  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  return 0;
}

/**
 *
 **/
static int
elfldr_raise_privileges(pid_t pid) {
  unsigned char caps[16] = { 0 };

  if(kernel_set_proc_rootdir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    klog_puts("kernel_set_proc_rootdir failed");
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    klog_puts("kernel_set_proc_jaildir failed");
    return -1;
  }
  if(kernel_set_ucred_prison(pid, KERNEL_ADDRESS_PRISON0)) {
    klog_puts("kernel_set_ucred_prison failed");
    return -1;
  }

  if(kernel_set_ucred_uid(pid, 0)) {
    klog_puts("kernel_set_ucred_uid failed");
    return -1;
  }

  if(kernel_get_ucred_caps(pid, caps)) {
    return -1;
  }
  caps[5] = 0x1c;   // ??
  caps[7] = 0x40;   // jail related?
  caps[15] |= 0x40; // jitshm
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }
  if(kernel_set_ucred_authid(pid, 0x3801000000000013l)) {
    klog_puts("kernel_set_ucred_authid failed");
    return -1;
  }

  return 0;
}

/**
 * Execute an ELF inside the process with the given pid.
 **/
int
elfldr_exec(pid_t pid, int stdio, uint8_t *elf, size_t elf_size) {
  int error = 0;

  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(stdio > 0) {
    stdio = pt_rdup(pid, getpid(), stdio);

    pt_close(pid, STDERR_FILENO);
    pt_close(pid, STDOUT_FILENO);
    pt_close(pid, STDIN_FILENO);

    pt_dup2(pid, stdio, STDIN_FILENO);
    pt_dup2(pid, stdio, STDOUT_FILENO);
    pt_dup2(pid, stdio, STDERR_FILENO);

    pt_close(pid, stdio);
  }

  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }

  if(pt_detach(pid, 0)) {
    LOG_PERROR("pt_detach");
    error = -1;
  }

  return error;
}

/**
 * Set the heap size for libc.
 **/
static int
elfldr_set_heap_size(pid_t pid, uint64_t size) {
  intptr_t sceLibcHeapExtendedAlloc;
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  uint32_t enabled = 1;
  intptr_t buf;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }
  if(pt_dynlib_get_proc_param(pid, buf, buf + 0x100)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }
  if(pt_copyout(pid, buf, &sceProcParam, sizeof(sceProcParam))
     || !sceProcParam) {
    LOG_PERROR("pt_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(pt_copyout(pid, sceProcParam + 56, &sceLibcParam, sizeof(sceLibcParam))) {
    LOG_PERROR("pt_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(pt_copyout(pid, sceLibcParam + 16, &sceLibcHeapSize,
                sizeof(sceLibcHeapSize))) {
    LOG_PERROR("pt_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(pt_copyin(pid, &size, sceLibcHeapSize, sizeof(size))) {
    LOG_PERROR("pt_copyin");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(size != UINT64_MAX) {
    pt_munmap(pid, buf, PAGE_SIZE);
    return 0;
  }

  // sceLibcHeapExtendedAlloc is not allocated when using SceSpZeroConf
  sceLibcHeapExtendedAlloc = buf;
  if(pt_copyin(pid, &sceLibcHeapExtendedAlloc, sceLibcParam + 32,
               sizeof(sceLibcHeapExtendedAlloc))) {
    LOG_PERROR("pt_copyin");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(pt_copyin(pid, &enabled, sceLibcHeapExtendedAlloc, sizeof(enabled))) {
    LOG_PERROR("pt_copyin");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  return 0;
}

/**
 * Set the name of a process.
 **/
static int
elfldr_set_procname(pid_t pid, const char *name) {
  char comm[MAXCOMLEN + 1];
  intptr_t buf;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }

  strncpy(comm, name, sizeof(comm) - 1);
  comm[sizeof(comm) - 1] = 0;

  pt_copyin(pid, comm, buf, strlen(comm) + 1);

  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}

/**
 *
 **/
static int
elfldr_rfork_entry(void *argv) {
  const char *SceSpZeroConf = "/system/vsh/app/NPXS21016/eboot.bin";
  struct sched_param sp;

  if(syscall(0x23b, 0)) {
    klog_perror("sys_budget_set");
    return 0;
  }

  if(open("/dev/deci_stdin", O_RDONLY) < 0) {
    klog_perror("open");
    return 0;
  }
  if(open("/dev/deci_stdout", O_WRONLY) < 0) {
    klog_perror("open");
    return 0;
  }
  if(open("/dev/deci_stderr", O_WRONLY) < 0) {
    klog_perror("open");
    return 0;
  }

  if(ptrace(PT_TRACE_ME, 0, 0, 0)) {
    klog_perror("ptrace");
    return 0;
  }

  sp.sched_priority = sched_get_priority_min(SCHED_RR);
  if(sched_setscheduler(0, SCHED_RR, &sp)) {
    LOG_PERROR("sched_setscheduler");
  }

  execve(SceSpZeroConf, argv, 0);

  klog_perror("execve");
  return 0;
}

/**
 * How long a new process is watched for a failure to start, in milliseconds,
 * and how many times it is spawned again.
 **/
#define SPAWN_WATCH_MS 1000
#define SPAWN_RETRIES 3

/**
 * The fewest modules, and the highest module handle, a host has had when it
 * reached main(), and the number of starts in a row that had more.
 **/
static int host_modules = 0;
static unsigned int host_handle = 0;
static int host_busy = 0;

/**
 * Check if the host process has begun to load libraries by itself, which
 * leaves it unable to load libraries for the payload. A host that has more
 * modules every time is taken as it is after a few starts.
 **/
static int
elfldr_host_busy(pid_t pid) {
  unsigned int hmax = 0;
  int n = 0;

  for(unsigned int h = 0; h < 64; h++) {
    dynlib_obj_t obj;

    if(kernel_dynlib_obj(pid, h, &obj) < 0) {
      continue;
    }
    n++;
    hmax = h;
  }

  if(!host_modules || (n <= host_modules && hmax <= host_handle)) {
    host_modules = n;
    host_handle = hmax;
    host_busy = 0;
    return 0;
  }

  if(++host_busy > 3) {
    host_modules = n;
    host_handle = hmax;
    host_busy = 0;
    return 0;
  }

  for(unsigned int h = host_handle + 1; h <= hmax; h++) {
    const char *name;
    dynlib_obj_t obj;
    char path[256] = { 0 };

    if(kernel_dynlib_obj(pid, h, &obj) < 0) {
      continue;
    }
    if(obj.path) {
      kernel_copyout(obj.path, path, sizeof(path) - 1);
    }
    name = path;
    for(const char *p = path; *p; p++) {
      if(*p == '/') {
        name = p + 1;
      }
    }
    LOG_PRINTF("Host process has loaded %s\n", name);
  }

  return 1;
}

/**
 * Get notified when a process exits.
 **/
static int
elfldr_watch(pid_t pid) {
  struct kevent evt;
  int kq;

  if((kq = kqueue()) < 0) {
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
  if(kevent(kq, &evt, 1, 0, 0, 0) < 0) {
    close(kq);
    return -1;
  }

  return kq;
}

/**
 * Check if a watched process exits with status 255 soon after it was started,
 * which is what the runtime of a payload does when it fails to load a library.
 **/
static int
elfldr_start_failed(int kq) {
  struct timespec ts = { .tv_sec = SPAWN_WATCH_MS / 1000,
                         .tv_nsec = SPAWN_WATCH_MS % 1000 * 1000000 };
  struct kevent evt;
  int status;
  int n;

  if(kq < 0) {
    return 0;
  }

  n = kevent(kq, 0, 0, &evt, 1, &ts);
  close(kq);

  if(n != 1 || !(evt.fflags & NOTE_EXIT)) {
    return 0;
  }

  status = evt.data;

  return WIFEXITED(status) && WEXITSTATUS(status) == 0xff;
}

/**
 * Execute an ELF inside a new process, and tell if it failed to start.
 **/
static pid_t
elfldr_spawn_once(int stdio, char *const argv[], uint8_t *elf,
                  size_t elf_size, int *failed) {
  uint8_t int3instr = 0xcc;
  struct kevent evt;
  intptr_t brkpoint;
  uint8_t orginstr;
  void *stack;
  pid_t pid;
  int kq;

  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }

  if((stack = mmap(NULL, MB(2), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
     == MAP_FAILED) {
    LOG_PERROR("mmap");
    close(kq);
    return -1;
  }

  if((pid = rfork_thread(RFPROC | RFCFDG | RFMEM, stack + MB(2),
                         elfldr_rfork_entry, (void *)argv))
     < 0) {
    LOG_PERROR("rfork_thread");
    munmap(stack, MB(2));
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    kill(pid, SIGKILL);
    munmap(stack, MB(2));
    close(kq);
    return -1;
  }

  for(int tries = 0; pt_attach(pid) == -1; tries++) {
    if(errno != EBUSY || tries >= 5000) {
      LOG_PERROR("pt_attach");
      kill(pid, SIGKILL);
      munmap(stack, MB(2));
      close(kq);
      return -1;
    }
    usleep(1000);
  }

  munmap(stack, MB(2));
  close(kq);

  if(pt_dynlib_process_needed_and_relocate(pid)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  if(elfldr_set_heap_size(pid, UINT64_MAX)) {
    LOG_PT_PERROR(pid, "elfldr_set_heap_size");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Insert a breakpoint at the eboot entry.
  if(!(brkpoint = kernel_dynlib_entry_addr(pid, 0))) {
    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  brkpoint += 58; // offset to invocation of main()

  if(pt_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    LOG_PERROR("pt_copyout");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(pt_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    LOG_PERROR("pt_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    LOG_PERROR("pt_continue");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    LOG_PERROR("waitpid");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(pt_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    LOG_PERROR("pt_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // A host that has begun to load libraries by itself makes the payload fail
  // to load its own, start over with a new process.
  if(elfldr_host_busy(pid)) {
    LOG_PUTS("Host process is not clean, starting over");
    pt_detach(pid, SIGKILL);
    *failed = 1;
    return pid;
  }

  // Execute the ELF
  elfldr_set_procname(pid, "Payload");
  kq = elfldr_watch(pid);
  if(elfldr_exec(pid, stdio, elf, elf_size)) {
    kill(pid, SIGKILL);
    if(kq >= 0) {
      close(kq);
    }
    return -1;
  }

  *failed = elfldr_start_failed(kq);

  return pid;
}

/**
 * Execute an ELF inside a new process. A payload that fails to start is
 * spawned again, since it tends to start fine the next time.
 **/
pid_t
elfldr_spawn(int stdio, char *const argv[], uint8_t *elf, size_t elf_size) {
  int failed = 0;
  pid_t pid;

  for(int tries = 0; tries <= SPAWN_RETRIES; tries++) {
    if(tries) {
      LOG_PRINTF("Payload failed to start, retrying (%d/%d)\n", tries,
                 SPAWN_RETRIES);
      usleep(100000);
    }

    pid = elfldr_spawn_once(stdio, argv, elf, elf_size, &failed);
    if(pid < 0 || !failed) {
      break;
    }
  }

  return pid;
}

/**
 * Read an ELF from a given socket. The memory is obtained from mmap().
 **/
int
elfldr_read(int fd, uint8_t **elf, size_t *elf_size) {
  Elf64_Shdr *shdr;
  Elf64_Ehdr ehdr;
  uint8_t *buf;
  uint8_t *bak;
  size_t size;
  off_t shend;
  size_t rem;

  if(recv(fd, &ehdr, sizeof(ehdr), MSG_WAITALL) != sizeof(ehdr)) {
    return -1;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E'
     || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
    errno = ENOEXEC;
    return -1;
  }

  if(ehdr.e_ident[EI_CLASS] != ELFCLASS64
     || ehdr.e_shentsize != sizeof(Elf64_Shdr) || !ehdr.e_shnum
     || ehdr.e_shoff < sizeof(ehdr)
     || ehdr.e_shoff > SIZE_MAX - ehdr.e_shnum * sizeof(Elf64_Shdr)) {
    errno = ENOEXEC;
    return -1;
  }

  size = ehdr.e_shoff + ehdr.e_shnum * sizeof(Elf64_Shdr);
  if((buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
     == MAP_FAILED) {
    return -1;
  }

  memcpy(buf, &ehdr, sizeof(ehdr));
  rem = size - sizeof(ehdr);
  if(recv(fd, buf + sizeof(ehdr), rem, MSG_WAITALL) != rem) {
    munmap(buf, size);
    return -1;
  }

  shend = 0;
  shdr = (Elf64_Shdr *)(buf + ehdr.e_shoff);
  for(int i = 0; i < ehdr.e_shnum; i++) {
    if(shdr[i].sh_type == SHT_NOBITS) {
      continue;
    }
    if(shdr[i].sh_size > SIZE_MAX - shdr[i].sh_offset) {
      munmap(buf, size);
      errno = ENOEXEC;
      return -1;
    }
    size_t end = shdr[i].sh_offset + shdr[i].sh_size;
    if(end > shend) {
      shend = end;
    }
  }

  // sections appear before section headers
  if(shend <= size) {
    *elf = buf;
    *elf_size = size;
    return 0;
  }

  bak = buf;
  if((buf = mmap(NULL, shend, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
     == MAP_FAILED) {
    munmap(bak, size);
    return -1;
  }

  memcpy(buf, bak, size);
  munmap(bak, size);
  rem = shend - size;
  if(recv(fd, buf + size, rem, MSG_WAITALL) != rem) {
    munmap(buf, shend);
    return -1;
  }

  *elf = buf;
  *elf_size = shend;

  return 0;
}
