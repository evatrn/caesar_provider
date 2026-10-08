# File: Makefile
# Date: 28/09/2026

CC = gcc
src = caesar.c
all: caesar

# Optimization turned off (-O0)
caesar:
	$(CC) -fPIC -shared -g -O0 -DCOMMITID=\"00\" $(src) -o caesar.so -lcrypto
