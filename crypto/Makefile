FLAGS = -std=gnu11 -Wall -Wextra -pedantic -ggdb 
EXTRA_FLAGS = -fsanitize=undefined -fsanitize=address -O2
# FLAGS += $(EXTRA_FLAGS)
DEFINITIONS = -D_DEBUG -Wno-unused-parameter

test: test.c chacha20.h sha512.h ed25519.h x25519.h poly1305.h
	gcc $(FLAGS) $(DEFINITIONS) $< -o $@

