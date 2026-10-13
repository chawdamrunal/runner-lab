FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

RUN sed -i 's/Types: deb/Types: deb deb-src/g' \
      /etc/apt/sources.list.d/ubuntu.sources \
    && grep '^Types: deb deb-src$' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
       build-essential \
       clang \
       dpkg-dev \
       libclang-rt-18-dev \
       libzstd-dev=1.5.5+dfsg2-2build1.1 \
    && apt-get build-dep -y libzstd=1.5.5+dfsg2-2build1.1 \
    && apt-get source libzstd=1.5.5+dfsg2-2build1.1 \
    && rm -rf /var/lib/apt/lists/*

RUN source_dir=$(find /build -mindepth 1 -maxdepth 1 -type d \
      -name 'libzstd-*' -print -quit) \
    && test -n "$source_dir" \
    && printf '%s\n' "$source_dir" \
      > /usr/local/share/f005-zstd-source-directory.txt \
    && cd "$source_dir" \
    && dpkg-parsechangelog -S Version \
      > /usr/local/share/f005-zstd-source-version.txt \
    && make -C lib clean \
    && make -C lib -j2 \
       CC=clang \
       CFLAGS='-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
       libzstd.a

COPY f005_zstd_systemd_fuzz.c /src/f005_zstd_systemd_fuzz.c
COPY f005_zstd_version.c /src/f005_zstd_version.c

RUN source_dir=$(cat /usr/local/share/f005-zstd-source-directory.txt) \
    && clang -O1 -g \
      -fsanitize=fuzzer,address,undefined \
      -fno-sanitize-recover=all \
      -fno-omit-frame-pointer \
      -I"$source_dir/lib" \
      -o /usr/local/bin/f005-zstd-systemd-fuzz \
      /src/f005_zstd_systemd_fuzz.c \
      "$source_dir/lib/libzstd.a" \
      -pthread \
    && clang -O1 -g \
      -fsanitize=fuzzer-no-link,address,undefined \
      -fno-sanitize-recover=all \
      -fno-omit-frame-pointer \
      -I"$source_dir/lib" \
      -o /usr/local/bin/f005-zstd-version \
      /src/f005_zstd_version.c \
      "$source_dir/lib/libzstd.a" \
      -pthread

ENV ASAN_OPTIONS="abort_on_error=1:disable_coredump=1:detect_leaks=0"
ENV UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

ENTRYPOINT ["/usr/local/bin/f005-zstd-systemd-fuzz"]
