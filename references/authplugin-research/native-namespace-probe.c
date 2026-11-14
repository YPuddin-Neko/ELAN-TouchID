#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct ProbeMessage {
    mach_msg_header_t header;
    uint32_t marker;
    int32_t pid;
};
struct ProbeReceive { struct ProbeMessage message; mach_msg_max_trailer_t trailer; };

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    const char *prefix = "io.github.hackintosh-tools.elan-namespace-";
    if (argc < 3 || strncmp(argv[2], prefix, strlen(prefix)) || strlen(argv[2]) >= 120) return 2;
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t status;
    if (!strcmp(argv[1], "--server") && argc == 4) {
        unsigned marker = (unsigned)strtoul(argv[3], NULL, 10);
        if (marker != 20 && marker != 40) return 2;
        status = bootstrap_check_in(bootstrap_port, argv[2], &port);
        printf("NAMESPACE_SERVER check_in=%d marker=%u pid=%d\n", status, marker, getpid());
        if (status) return 3;
        for (unsigned attempt = 0; attempt < 6; attempt++) {
        struct ProbeReceive request = {0};
        status = mach_msg(&request.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                          sizeof(request), port, 20000, MACH_PORT_NULL);
        if (status) { printf("NAMESPACE_SERVER receive=%d\n", status); return 4; }
        if (request.message.header.msgh_id != 0x454c414e ||
            (request.message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
            mach_msg_destroy(&request.message.header); return 5;
        }
        struct ProbeMessage reply = {0};
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_size = sizeof(reply);
        reply.header.msgh_remote_port = request.message.header.msgh_remote_port;
        reply.header.msgh_id = 0x454c414f;
        reply.marker = marker; reply.pid = getpid();
        status = mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(reply), 0,
                          MACH_PORT_NULL, 3000, MACH_PORT_NULL);
        printf("NAMESPACE_SERVER reply=%d\n", status);
        if (status) return 6;
        }
        return 0;
    }
    if (strcmp(argv[1], "--client") || argc != 3) return 2;
    status = bootstrap_look_up(bootstrap_port, argv[2], &port);
    printf("NAMESPACE_CLIENT lookup=%d uid=%u\n", status, getuid());
    if (status) return 7;
    mach_port_t replyPort = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort)) return 8;
    struct ProbeMessage request = {0};
    request.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    request.header.msgh_size = sizeof(request);
    request.header.msgh_remote_port = port;
    request.header.msgh_local_port = replyPort;
    request.header.msgh_id = 0x454c414e;
    status = mach_msg(&request.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(request), 0,
                      MACH_PORT_NULL, 3000, MACH_PORT_NULL);
    struct ProbeReceive reply = {0};
    if (!status) status = mach_msg(&reply.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                  sizeof(reply), replyPort, 5000, MACH_PORT_NULL);
    int valid = !status && reply.message.header.msgh_id == 0x454c414f &&
                !(reply.message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
                (reply.message.marker == 20 || reply.message.marker == 40) && reply.message.pid > 1;
    printf("NAMESPACE_CLIENT reply=%d marker=%u server_pid=%d valid=%d\n", status,
           reply.message.marker, reply.message.pid, valid);
    mach_port_deallocate(mach_task_self(), port);
    mach_port_mod_refs(mach_task_self(), replyPort, MACH_PORT_RIGHT_RECEIVE, -1);
    return valid ? 0 : 9;
}
