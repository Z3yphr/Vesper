# Makefile for building C modules for Vesper project

# Compiler and flags
default_compiler = gcc
CC = $(CC_OVERRIDE)$(if $(CC_OVERRIDE),,$(default_compiler))
CFLAGS = -Wall -O2 -shared -fPIC

# Output DLL/shared library name (Windows)
TARGET = src/simple_hash.dll
SRC = src/simple_hash.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	del /Q $(TARGET) 2>NUL || rm -f $(TARGET)

.PHONY: all clean
