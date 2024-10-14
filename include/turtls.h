#ifndef TURTLS_H
#define TURTLS_H
#include <sys/types.h>
#include <stddef.h>
struct State;

struct State *shake_hands(ssize_t (*write)(void *, size_t), ssize_t (*read)(void *, size_t));
#endif
