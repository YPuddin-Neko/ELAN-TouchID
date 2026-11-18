#pragma once
#include <errno.h>
#include <poll.h>
#include <unistd.h>

enum class NativeBrokerStop { Running, Normal, Error };

static inline NativeBrokerStop nativeBrokerControllerStop(int fd) {
    if (fd < 0) return NativeBrokerStop::Error;
    pollfd control {fd, POLLIN, 0};
    int ready;
    do { ready = poll(&control, 1, 0); } while (ready < 0 && errno == EINTR);
    if (ready < 0 || (control.revents & (POLLERR | POLLNVAL))) return NativeBrokerStop::Error;
    if (!ready) return NativeBrokerStop::Running;
    if (!(control.revents & (POLLIN | POLLHUP))) return NativeBrokerStop::Error;
    // A closed pipe can still contain data; only an empty pipe is a normal lease end.
    char byte;
    ssize_t count;
    do { count = read(fd, &byte, 1); } while (count < 0 && errno == EINTR);
    return count == 0 ? NativeBrokerStop::Normal : NativeBrokerStop::Error;
}
