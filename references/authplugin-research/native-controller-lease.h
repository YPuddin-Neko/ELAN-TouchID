#pragma once
#include <stdbool.h>
#include <sys/stat.h>
#include <poll.h>
#include <errno.h>

static inline bool nativeControllerLeaseValid(int fd) {
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISFIFO(info.st_mode);
}

static inline bool nativeControllerLeaseAlive(int fd) {
    if (fd < 0) return false;
    struct pollfd control = {fd, POLLIN, 0};
    int result;
    do { result = poll(&control, 1, 0); } while (result < 0 && errno == EINTR);
    // The controller holds its pipe open without writing. Data or EOF stops the child.
    return result == 0;
}
