#define _GNU_SOURCE

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

static int frame_callback(Dwfl_Frame *frame, void *argument) {
  Dwarf_Addr program_counter = 0;
  bool activation = false;

  (void)argument;
  if (!dwfl_frame_pc(frame, &program_counter, &activation))
    return DWARF_CB_ABORT;
  return DWARF_CB_OK;
}

static int thread_callback(Dwfl_Thread *thread, void *argument) {
  if (dwfl_thread_getframes(thread, frame_callback, argument) < 0)
    return DWARF_CB_ABORT;
  return DWARF_CB_OK;
}

static int module_callback(Dwfl_Module *module, void **userdata,
                           const char *name, Dwarf_Addr start, void *argument) {
  Dwarf_Addr bias = 0;

  (void)userdata;
  (void)name;
  (void)start;
  (void)argument;
  (void)dwfl_module_getelf(module, &bias);
  (void)dwfl_module_getdwarf(module, &bias);
  return DWARF_CB_OK;
}

static int write_all(int fd, const uint8_t *data, size_t size) {
  size_t offset = 0;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);
    if (written <= 0)
      return -1;
    offset += (size_t)written;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static char *debuginfo_path = "";
  const Dwfl_Callbacks callbacks = {
      .find_elf = dwfl_build_id_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .section_address = dwfl_offline_section_address,
      .debuginfo_path = &debuginfo_path,
  };
  GElf_Ehdr header;
  Dwfl *dwfl = NULL;
  Elf *elf = NULL;
  int fd = -1;

  if (size == 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    return 0;
  if (elf_version(EV_CURRENT) == EV_NONE)
    return 0;
  fd = memfd_create("f005-core-native-fuzz", MFD_CLOEXEC);
  if (fd < 0 || write_all(fd, data, size) != 0 || lseek(fd, 0, SEEK_SET) < 0)
    goto cleanup;
  elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
  if (elf == NULL || gelf_getehdr(elf, &header) == NULL ||
      header.e_type != ET_CORE)
    goto cleanup;

  dwfl = dwfl_begin(&callbacks);
  if (dwfl == NULL || dwfl_core_file_report(dwfl, elf, NULL) < 0 ||
      dwfl_report_end(dwfl, NULL, NULL) != 0)
    goto cleanup;
  if (dwfl_getmodules(dwfl, module_callback, NULL, 0) < 0)
    goto cleanup;
  if (dwfl_core_file_attach(dwfl, elf) < 0)
    goto cleanup;
  (void)dwfl_getthreads(dwfl, thread_callback, NULL);

cleanup:
  if (dwfl != NULL)
    dwfl_end(dwfl);
  if (elf != NULL)
    elf_end(elf);
  if (fd >= 0)
    close(fd);
  return 0;
}
