# Makefile

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror -pedantic

COMMONSRC = src/common/log.c src/common/sha256.c
FSSRC = src/fs/scan.c src/fs/manifest.c
SYNCSRC = src/sync/diff.c
PROTOSRC = src/proto/frame.c
NETSRC = src/net/client.c src/net/server.c
SRC = src/main.c $(COMMONSRC) $(FSSRC) $(SYNCSRC) $(PROTOSRC) $(NETSRC)

TARGET = filesync

all: clean build

build:
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
