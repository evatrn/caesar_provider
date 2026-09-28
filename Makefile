# File: Makefile
# Date: 28/09/2026

CC = gcc
src = caesar.c

all: caesar

caesar:
	$(CC) -fPIC -shared $(src) -o caesar.so -lcrypto
