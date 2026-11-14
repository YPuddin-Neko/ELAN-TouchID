#include "native-controller-lease.h"
#include <cassert>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    int ends[2]; assert(pipe(ends) == 0);
    assert(nativeControllerLeaseValid(ends[0]) && nativeControllerLeaseAlive(ends[0]));
    close(ends[1]);
    assert(!nativeControllerLeaseAlive(ends[0])); close(ends[0]);
    assert(!nativeControllerLeaseValid(ends[0]) && !nativeControllerLeaseAlive(ends[0]));
    assert(pipe(ends) == 0);
    assert(write(ends[1], "x", 1) == 1);
    assert(!nativeControllerLeaseAlive(ends[0])); close(ends[0]); close(ends[1]);
    int file = open("/dev/null", O_RDONLY); assert(file >= 0);
    assert(!nativeControllerLeaseValid(file)); close(file);
    assert(!nativeControllerLeaseValid(-1) && !nativeControllerLeaseAlive(-1));
    puts("CONTROLLER_LEASE empty_pipe_keeps_alive eof_data_invalid_stop passed=1");
}
