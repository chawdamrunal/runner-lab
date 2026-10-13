#define _GNU_SOURCE

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

struct note_span {
  size_t header_offset;
  size_t descriptor_offset;
  size_t descriptor_size;
};

struct load_span {
  size_t header_offset;
  size_t file_offset;
  size_t file_size;
  size_t memory_size;
};

static bool range_is_valid(size_t offset, size_t length, size_t size) {
  return offset <= size && length <= size - offset;
}

static bool align_four(size_t value, size_t *result) {
  if (value > SIZE_MAX - 3)
    return false;
  *result = (value + 3) & ~(size_t)3;
  return true;
}

static size_t collect_spans(uint8_t *data, size_t size,
                            struct note_span *notes, size_t *note_count,
                            struct load_span *loads, size_t *load_count) {
  Elf64_Ehdr header;
  size_t program_table_size = 0;

  *note_count = 0;
  *load_count = 0;
  if (size < sizeof(header))
    return 0;
  memcpy(&header, data, sizeof(header));
  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_type != ET_CORE ||
      header.e_phentsize < sizeof(Elf64_Phdr) || header.e_phnum == 0 ||
      __builtin_mul_overflow((size_t)header.e_phentsize,
                             (size_t)header.e_phnum,
                             &program_table_size) ||
      !range_is_valid((size_t)header.e_phoff, program_table_size, size))
    return 0;

  for (size_t index = 0; index < header.e_phnum; index++) {
    size_t header_offset =
        (size_t)header.e_phoff + index * (size_t)header.e_phentsize;
    Elf64_Phdr program_header;

    memcpy(&program_header, data + header_offset, sizeof(program_header));
    if (program_header.p_type == PT_LOAD && program_header.p_filesz > 0 &&
        range_is_valid((size_t)program_header.p_offset,
                       (size_t)program_header.p_filesz, size) &&
        *load_count < 64) {
      loads[*load_count] =
          (struct load_span){.header_offset = header_offset,
                             .file_offset = (size_t)program_header.p_offset,
                             .file_size = (size_t)program_header.p_filesz,
                             .memory_size = (size_t)program_header.p_memsz};
      (*load_count)++;
    }
    if (program_header.p_type != PT_NOTE ||
        !range_is_valid((size_t)program_header.p_offset,
                        (size_t)program_header.p_filesz, size))
      continue;

    size_t note_offset = (size_t)program_header.p_offset;
    const size_t note_end = note_offset + (size_t)program_header.p_filesz;
    while (range_is_valid(note_offset, 3 * sizeof(uint32_t), note_end)) {
      uint32_t note_header[3];
      size_t name_end = 0;
      size_t descriptor_offset = 0;
      size_t descriptor_end = 0;

      memcpy(note_header, data + note_offset, sizeof(note_header));
      if (__builtin_add_overflow(note_offset, sizeof(note_header), &name_end) ||
          __builtin_add_overflow(name_end, (size_t)note_header[0], &name_end) ||
          !align_four(name_end, &descriptor_offset) ||
          __builtin_add_overflow(descriptor_offset,
                                 (size_t)note_header[1], &descriptor_end) ||
          !align_four(descriptor_end, &descriptor_end) ||
          descriptor_end > note_end)
        break;
      if (note_header[1] > 0 && *note_count < 64) {
        notes[*note_count] =
            (struct note_span){.header_offset = note_offset,
                               .descriptor_offset = descriptor_offset,
                               .descriptor_size = (size_t)note_header[1]};
        (*note_count)++;
      }
      if (descriptor_end <= note_offset)
        break;
      note_offset = descriptor_end;
    }
  }
  return *note_count + *load_count;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  static const uint32_t note_types[] = {
      1, 2, 3, 6, 0x46494c45, 0x53494749, 0x202, 0x205,
  };
  struct note_span notes[64];
  struct load_span loads[64];
  size_t note_count = 0;
  size_t load_count = 0;

  if (collect_spans(data, size, notes, &note_count, loads, &load_count) == 0)
    return LLVMFuzzerMutate(data, size, max_size);

  switch (seed % 5U) {
  case 0:
  case 1:
    if (note_count > 0) {
      const struct note_span *note = &notes[(seed / 5U) % note_count];
      (void)LLVMFuzzerMutate(data + note->descriptor_offset,
                             note->descriptor_size, note->descriptor_size);
      return size;
    }
    break;
  case 2:
    if (note_count > 0) {
      const struct note_span *note = &notes[(seed / 5U) % note_count];
      uint32_t type = note_types[(seed / 11U) %
                                 (sizeof(note_types) / sizeof(note_types[0]))];
      memcpy(data + note->header_offset + 2 * sizeof(uint32_t), &type,
             sizeof(type));
      return size;
    }
    break;
  case 3:
    if (load_count > 0) {
      const struct load_span *load = &loads[(seed / 5U) % load_count];
      (void)LLVMFuzzerMutate(data + load->file_offset, load->file_size,
                             load->file_size);
      return size;
    }
    break;
  case 4:
    if (load_count > 0) {
      const struct load_span *load = &loads[(seed / 5U) % load_count];
      Elf64_Phdr program_header;
      size_t available = size - load->file_offset;
      size_t upper = load->memory_size;

      if (upper > available)
        upper = available;
      memcpy(&program_header, data + load->header_offset,
             sizeof(program_header));
      program_header.p_filesz = upper == 0 ? 0 : (seed / 17U) % (upper + 1);
      if (program_header.p_memsz < program_header.p_filesz)
        program_header.p_memsz = program_header.p_filesz;
      memcpy(data + load->header_offset, &program_header,
             sizeof(program_header));
      return size;
    }
    break;
  }
  return LLVMFuzzerMutate(data, size, max_size);
}

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
