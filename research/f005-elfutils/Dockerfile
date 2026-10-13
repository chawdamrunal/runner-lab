FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       gcc \
       libc6-dev \
       libdw-dev=0.190-1.1ubuntu0.1 \
       libelf-dev=0.190-1.1ubuntu0.1 \
    && rm -rf /var/lib/apt/lists/*

COPY f005_libdwfl_replay.c /src/f005_libdwfl_replay.c

RUN gcc -O2 -g -Wall -Wextra -Werror \
      -o /usr/local/bin/f005-libdwfl-replay \
      /src/f005_libdwfl_replay.c \
      -ldw -lelf \
    && dpkg-query -W -f='${Package}=${Version}\n' \
      libdw1t64 libdw-dev libelf1t64 libelf-dev \
      > /usr/local/share/f005-elfutils-versions.txt

ENV DEBUGINFOD_URLS=""

ENTRYPOINT ["/usr/local/bin/f005-libdwfl-replay"]
