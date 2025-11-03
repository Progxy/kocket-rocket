FLAGS = -std=gnu11 -Wall -Wextra -pedantic -ggdb
DEFINITIONS = -D_DEBUG

test: test.c chacha20.h sha512.h ed25519.h x25519.h poly1305.h
	gcc $(FLAGS) $(DEFINITIONS) $< -o $@

