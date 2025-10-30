FLAGS = -std=gnu11 -Wall -Wextra -pedantic -ggdb
DEFINITIONS = -D_DEBUG
RELAX_FLAGS = -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable

test: test.c chacha20.h sha512.h ed25519.h x25519.h poly1305.h
	gcc $(FLAGS) $(RELAX_FLAGS) $(DEFINITIONS) $< -o $@

