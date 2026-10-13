#define _GNU_SOURCE

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

static char *debuginfo_path = "";

static const Dwfl_Callbacks callbacks = {
    .find_elf = NULL,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = NULL,
    .debuginfo_path = &debuginfo_path,
};

int main(int argc, char **argv) {
  Dwarf_Addr bias = 0;
  Dwfl_Module *module;
  Dwfl *dwfl;
  Dwarf *dwarf;

  if (argc != 2) {
    fprintf(stderr, "usage: %s ELF\n", argv[0]);
    return 2;
  }

  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    fprintf(stderr, "PR_SET_DUMPABLE failed: errno=%d\n", errno);
    return 2;
  }
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
    fprintf(stderr, "dumpability readback was not zero\n");
    return 2;
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "elf_version failed: %s\n", elf_errmsg(-1));
    return 2;
  }

  dwfl = dwfl_begin(&callbacks);
  if (dwfl == NULL) {
    fprintf(stderr, "dwfl_begin failed: %s\n", dwfl_errmsg(-1));
    return 2;
  }

  dwfl_report_begin(dwfl);
  module = dwfl_report_offline(dwfl, argv[1], argv[1], -1);
  if (module == NULL) {
    fprintf(stderr, "dwfl_report_offline rejected input: %s\n", dwfl_errmsg(-1));
    dwfl_end(dwfl);
    return 4;
  }

  dwarf = dwfl_module_getdwarf(module, &bias);
  printf("F005_LIBDWFL_RESULT input=%s dwarf=%s bias=%#llx\n", argv[1],
         dwarf == NULL ? "absent" : "present", (unsigned long long)bias);
  dwfl_end(dwfl);
  return 0;
}
