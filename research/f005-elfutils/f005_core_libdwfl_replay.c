#define _GNU_SOURCE

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
  Dwarf *dwarf;
  Elf *elf;

  (void)userdata;
  (void)start;
  (void)argument;
  elf = dwfl_module_getelf(module, &bias);
  dwarf = dwfl_module_getdwarf(module, &bias);
  printf("F005_CORE_MODULE name=%s elf=%s dwarf=%s bias=%#llx\n",
         name == NULL ? "(null)" : name, elf == NULL ? "absent" : "present",
         dwarf == NULL ? "absent" : "present", (unsigned long long)bias);
  return DWARF_CB_OK;
}

static void fail(const char *operation) {
  fprintf(stderr, "F005_CORE_REPLAY_ERROR operation=%s elf=%s dwfl=%s errno=%d\n",
          operation, elf_errmsg(-1), dwfl_errmsg(-1), errno);
  exit(4);
}

int main(int argc, char **argv) {
  static char *debuginfo_path = "";
  const Dwfl_Callbacks callbacks = {
      .find_elf = dwfl_build_id_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .section_address = dwfl_offline_section_address,
      .debuginfo_path = &debuginfo_path,
  };
  GElf_Ehdr header;
  Dwfl *dwfl;
  Elf *elf;
  int fd;

  if (argc != 2) {
    fprintf(stderr, "usage: %s CORE\n", argv[0]);
    return 2;
  }
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    fail("pr-set-dumpable");
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
    fail("dumpability-readback");
  if (elf_version(EV_CURRENT) == EV_NONE)
    fail("elf-version");

  fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    fail("open");
  elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
  if (elf == NULL)
    fail("elf-begin");
  if (gelf_getehdr(elf, &header) == NULL || header.e_type != ET_CORE)
    fail("outer-object-is-not-core");

  dwfl = dwfl_begin(&callbacks);
  if (dwfl == NULL)
    fail("dwfl-begin");
  if (dwfl_core_file_report(dwfl, elf, NULL) < 0)
    fail("core-file-report");
  if (dwfl_report_end(dwfl, NULL, NULL) != 0)
    fail("report-end");
  if (dwfl_getmodules(dwfl, module_callback, NULL, 0) < 0)
    fail("getmodules");
  if (dwfl_core_file_attach(dwfl, elf) < 0)
    fail("core-file-attach");
  if (dwfl_getthreads(dwfl, thread_callback, NULL) < 0)
    fail("getthreads");

  printf("F005_CORE_REPLAY_RESULT input=%s status=parsed\n", argv[1]);
  dwfl_end(dwfl);
  elf_end(elf);
  close(fd);
  return 0;
}
