#include "kernel-provider/NativePlatformCache.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_special_ports.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>

struct TaskMessage {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t task;
};
struct TaskReceive { TaskMessage message; mach_msg_max_trailer_t trailer; };

static int readTask(void *context, uint64_t address, void *output, size_t length) {
    mach_vm_size_t actual = 0;
    kern_return_t status = mach_vm_read_overwrite(static_cast<mach_port_t>(reinterpret_cast<uintptr_t>(context)),
        address, length, reinterpret_cast<mach_vm_address_t>(output), &actual);
    return status ? status : actual == length ? 0 : NativePlatformInvalid;
}
static int writeTask(void *context, uint64_t address, const void *bytes, size_t length) {
    return mach_vm_write(static_cast<mach_port_t>(reinterpret_cast<uintptr_t>(context)), address,
                         reinterpret_cast<vm_offset_t>(bytes), static_cast<mach_msg_type_number_t>(length));
}
static bool writableTask(void *context, uint64_t address, size_t length) {
    mach_vm_address_t start = address;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info {};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t status = mach_vm_region(static_cast<mach_port_t>(reinterpret_cast<uintptr_t>(context)),
        &start, &size, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object);
    if (object) mach_port_deallocate(mach_task_self(), object);
    return !status && start <= address && address - start <= size && length <= size - (address - start) &&
           (info.protection & VM_PROT_WRITE);
}
static int readByte(int fd) {
    pollfd poller {fd, POLLIN, 0};
    int ready;
    do { ready = poll(&poller, 1, 5000); } while (ready < 0 && errno == EINTR);
    unsigned char byte;
    return ready > 0 && read(fd, &byte, 1) == 1 ? byte : -1;
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--cooperating-child")) return 2;
    setbuf(stdout, nullptr);
    signal(SIGPIPE, SIG_IGN);
    char build[64] = {};
    size_t buildSize = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &buildSize, nullptr, 0) || strcmp(build, "24H32")) return 3;
    void *framework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_LAZY | RTLD_LOCAL);
    auto platform = reinterpret_cast<bool (*)(char *)>(framework ? dlsym(framework, "isTouchIDPlatformWithFailure") : nullptr);
    char failure = 0;
    if (!platform || platform(&failure)) return 4;
    uint64_t function = reinterpret_cast<uint64_t>(platform);
    NativePlatformCacheLocation location {};
    if (!nativePlatformCacheLocation(reinterpret_cast<const uint8_t *>(platform), 0x245, function, location)) return 5;
    printf("PLATFORM_PROCESS baseline=0 build=%s system_processes_touched=0\n", build);
    int commands[2], replies[2];
    if (pipe(commands) || pipe(replies)) return 6;
    mach_port_t rendezvous = MACH_PORT_NULL, originalBootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &originalBootstrap) ||
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rendezvous) ||
        mach_port_insert_right(mach_task_self(), rendezvous, rendezvous, MACH_MSG_TYPE_MAKE_SEND)) return 7;
    if (task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, rendezvous)) return 8;
    pid_t child = fork();
    if (child == 0) {
        // No Objective-C work after fork. The platform function takes its initialized cache path.
        close(commands[1]); close(replies[0]);
        mach_port_t parentPort = MACH_PORT_NULL;
        if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &parentPort)) _exit(30);
        TaskMessage message {};
        message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
        message.header.msgh_size = sizeof(message);
        message.header.msgh_remote_port = parentPort;
        message.header.msgh_id = 0x454c414e;
        message.body.msgh_descriptor_count = 1;
        message.task.name = mach_task_self();
        message.task.disposition = MACH_MSG_TYPE_COPY_SEND;
        message.task.type = MACH_MSG_PORT_DESCRIPTOR;
        if (mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(message), 0,
                     MACH_PORT_NULL, 5000, MACH_PORT_NULL)) _exit(31);
        for (unsigned index = 0; index < 3; index++) {
            if (readByte(commands[0]) != 'q') _exit(32);
            unsigned char value = platform(&failure) ? 1 : 0;
            if (write(replies[1], &value, 1) != 1) _exit(33);
        }
        _exit(0);
    }
    int bootstrapRestore = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, originalBootstrap);
    mach_port_deallocate(mach_task_self(), originalBootstrap);
    close(commands[0]); close(replies[1]);
    if (child < 0) return 9;
    int result = 1;
    mach_port_t childTask = MACH_PORT_NULL;
    NativePlatformCacheState state {};
    NativePlatformCacheAPI api {nullptr, readTask, writeTask, writableTask};
    do {
        if (bootstrapRestore) break;
        TaskReceive received {};
        kern_return_t status = mach_msg(&received.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
            sizeof(received), rendezvous, 5000, MACH_PORT_NULL);
        if (status) { printf("PLATFORM_PROCESS receive=%d\n", status); break; }
        TaskMessage &message = received.message;
        if (!(message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) || message.header.msgh_id != 0x454c414e ||
            message.body.msgh_descriptor_count != 1 || message.task.type != MACH_MSG_PORT_DESCRIPTOR) {
            mach_msg_destroy(&message.header); break;
        }
        childTask = message.task.name;
        pid_t peer = 0;
        if (pid_for_task(childTask, &peer) || peer != child) break;
        api.context = reinterpret_cast<void *>(static_cast<uintptr_t>(childTask));
        if (write(commands[1], "q", 1) != 1 || readByte(replies[0]) != 0) break;
        int enable = nativePlatformEnable(api, function, state);
        if (enable) { printf("PLATFORM_PROCESS enable=%d pending=%d\n", enable, state.restorePending); break; }
        if (write(commands[1], "q", 1) != 1) break;
        int enabled = readByte(replies[0]);
        int parentAfter = platform(&failure);
        int restore = nativePlatformRestore(api, state);
        if (write(commands[1], "q", 1) != 1) break;
        int restored = readByte(replies[0]);
        printf("PLATFORM_PROCESS child_enabled=%d parent_unchanged=%d restore=%d child_restored=%d pending=%d\n",
               enabled, parentAfter == 0, restore, restored, state.restorePending);
        if (enabled == 1 && parentAfter == 0 && !restore && restored == 0 && !state.restorePending) result = 0;
    } while (false);
    if (state.restorePending) {
        int restore = nativePlatformRestore(api, state);
        printf("PLATFORM_PROCESS cleanup_restore=%d pending=%d\n", restore, state.restorePending);
    }
    close(commands[1]); close(replies[0]);
    if (result) kill(child, SIGTERM);
    int waitStatus = 0;
    pid_t waited;
    do { waited = waitpid(child, &waitStatus, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus)) result = 1;
    if (childTask) mach_port_deallocate(mach_task_self(), childTask);
    mach_port_deallocate(mach_task_self(), rendezvous);
    mach_port_mod_refs(mach_task_self(), rendezvous, MACH_PORT_RIGHT_RECEIVE, -1);
    printf("PLATFORM_PROCESS_DONE status=%d child_reaped=%d bootstrap_restored=%d credentials_submitted=0\n",
           result, waited == child, !bootstrapRestore);
    return result;
}
