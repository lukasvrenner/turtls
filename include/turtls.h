#ifndef TURTLS_H
#define TURTLS_H
#include <sys/types.h>
#include <stddef.h>
struct State;

struct State *shake_hands(int fd, ssize_t (*write)(int, void *, size_t), ssize_t (*read)(int, void *, size_t));
#endif
