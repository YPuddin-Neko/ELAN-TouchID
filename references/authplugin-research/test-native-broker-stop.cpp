#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <signal.h>
#include <string>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "native-provider-wire.h"
#include "native-broker-production-state.inc"

static constexpr int Listener = 10000, Peer = 10001, Kernel = 10002, Expected = 10003;

static NativeProviderWireRequest validRequest() {
    NativeProviderWireRequest request {};
    request.magic = NativeProviderWireMagic;
    request.selector = ElanProviderBegin;
    request.length = static_cast<uint32_t>(nativeProviderInputSize(request.selector));
    return request;
}

struct TestIO {
    int lease[2] {-1, -1};
    bool readerOpen = true;
    time_t now = 100;
    std::vector<uint8_t> input, output;
    size_t offset = 0, readChunk = 4096, writeChunk = 4096, readErrorAt = 0, writeErrorAt = 0;
    int leasePollError = 0, leaseReadError = 0, listenerPollError = 0, peerPollError = 0;
    int listenerReady = 1, peerReady = 1, acceptError = 0, readError = 0, writeError = 0;
    int readInterruptions = 0, writeInterruptions = 0, recoverStatus = 0;
    short listenerEvents = POLLIN, peerEvents = POLLIN;
    bool zeroWrite = false, rejectRequestPeer = false;
    std::string setupFailure;
    int kernelCalls = 0, recoverCalls = 0, closedKernel = 0, closedListener = 0, closedPeer = 0;
    int socketRemovals = 0, peerShutdowns = 0, allowedCalls = 0, steps = 0;
    std::map<std::string, int> events;
    std::function<void(const std::string &)> on;

    TestIO() {
        assert(pipe(lease) == 0);
        request(validRequest());
    }
    ~TestIO() {
        if (readerOpen) assert(::close(lease[0]) == 0);
        if (lease[1] >= 0) assert(::close(lease[1]) == 0);
    }
    void request(const NativeProviderWireRequest &value) {
        auto *bytes = reinterpret_cast<const uint8_t *>(&value);
        input.assign(bytes, bytes + sizeof(value));
    }
    void endLease() {
        if (lease[1] >= 0) { assert(::close(lease[1]) == 0); lease[1] = -1; }
    }
    void leaseData() { assert(::write(lease[1], "x", 1) == 1); }
    void invalidateLease() { assert(readerOpen && ::close(lease[0]) == 0); readerOpen = false; }
    void fire(const std::string &event) {
        assert(++steps < 500);
        ++events[event];
        if (on) on(event);
    }
};
static TestIO *io;

static int mockPoll(pollfd *descriptor, nfds_t count, int timeout) {
    assert(count == 1);
    if (descriptor->fd == STDIN_FILENO) {
        assert(timeout == 0);
        io->fire("lease-poll");
        if (io->leasePollError) {
            errno = io->leasePollError;
            if (errno == EINTR) io->leasePollError = 0;
            return -1;
        }
        pollfd lease {io->lease[0], descriptor->events, 0};
        int result = ::poll(&lease, 1, 0);
        descriptor->revents = lease.revents;
        return result;
    }
    assert(timeout == 250 && (descriptor->fd == Listener || descriptor->fd == Peer));
    bool listener = descriptor->fd == Listener;
    io->fire(listener ? "listener-poll" : "peer-poll");
    int &error = listener ? io->listenerPollError : io->peerPollError;
    if (error) { errno = error; if (error == EINTR) error = 0; return -1; }
    descriptor->revents = listener ? io->listenerEvents : io->peerEvents;
    return listener ? io->listenerReady : io->peerReady;
}

static ssize_t mockRead(int fd, void *buffer, size_t length) {
    if (fd == STDIN_FILENO) {
        io->fire("lease-read");
        if (io->leaseReadError) { errno = io->leaseReadError; io->leaseReadError = 0; return -1; }
        return ::read(io->lease[0], buffer, length);
    }
    assert(fd == Peer);
    io->fire("request-read");
    if (io->readInterruptions) { --io->readInterruptions; errno = EINTR; return -1; }
    if (io->readError && io->offset >= io->readErrorAt) { errno = io->readError; return -1; }
    size_t count = std::min({length, io->readChunk, io->input.size() - io->offset});
    if (count) memcpy(buffer, io->input.data() + io->offset, count);
    io->offset += count;
    return static_cast<ssize_t>(count);
}

static ssize_t mockWrite(int fd, const void *buffer, size_t length) {
    assert(fd == Peer);
    io->fire("reply-write");
    if (io->writeInterruptions) { --io->writeInterruptions; errno = EINTR; return -1; }
    if (io->writeError && io->output.size() >= io->writeErrorAt) { errno = io->writeError; return -1; }
    if (io->zeroWrite) return 0;
    size_t count = std::min(length, io->writeChunk);
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    io->output.insert(io->output.end(), bytes, bytes + count);
    return static_cast<ssize_t>(count);
}

static time_t mockTime(time_t *value) {
    io->fire("time");
    if (value) *value = io->now;
    return io->now;
}
static int mockAccept(int fd, sockaddr *address, socklen_t *length) {
    assert(fd == Listener && !address && !length);
    io->fire("accept");
    if (io->acceptError) {
        errno = io->acceptError;
        if (errno == EINTR) io->acceptError = 0;
        return -1;
    }
    return Peer;
}
static bool allowedPeer(int fd, int expected) {
    assert(fd == Peer && expected == Expected);
    ++io->allowedCalls;
    io->fire("allowed-peer");
    return !(io->rejectRequestPeer && io->allowedCalls > 1);
}
static bool brokerSessionCurrent(bool pinned) {
    io->fire(pinned ? "pinned-session" : "initial-session");
    return io->setupFailure != (pinned ? "pinned-session" : "initial-session");
}
static int mockChown(const char *path, uid_t uid, gid_t gid) {
    assert(!strcmp(path, NativeProviderSocket) && uid == 501 && gid == 20);
    return io->setupFailure == "chown" ? -1 : 0;
}
static int mockChmod(const char *path, mode_t mode) {
    assert(!strcmp(path, NativeProviderSocket) && mode == 0600);
    return io->setupFailure == "chmod" ? -1 : 0;
}
static int mockListen(int fd, int backlog) {
    assert(fd == Listener && backlog == 2);
    return io->setupFailure == "listen" ? -1 : 0;
}
static int mockSetsockopt(int fd, int level, int name, const void *, socklen_t length) {
    assert(fd == Peer && level == SOL_SOCKET && length == sizeof(timeval));
    assert(name == SO_RCVTIMEO || name == SO_SNDTIMEO);
    return io->setupFailure == (name == SO_RCVTIMEO ? "receive-timeout" : "send-timeout") ? -1 : 0;
}
static int mockShutdown(int fd, int how) {
    assert(fd == Peer && how == SHUT_RDWR); ++io->peerShutdowns; return 0;
}
static int mockClose(int fd) {
    assert(fd == Listener || fd == Peer);
    if (fd == Listener) ++io->closedListener; else ++io->closedPeer;
    return 0;
}
static int mockUnlink(const char *path) {
    assert(!strcmp(path, NativeProviderSocket)); ++io->socketRemovals; return 0;
}
static int IOServiceClose(int connection) {
    assert(connection == Kernel); ++io->closedKernel; return 0;
}
static int recoverProvider(int connection, NativeProviderReport *report = nullptr) {
    assert(connection == Kernel);
    ++io->recoverCalls;
    io->fire("recover");
    if (report) report->abi = 1;
    return io->recoverStatus;
}
static int recoverSettings(int, NativePlatformProcessReport &) { assert(false); return 1; }
static constexpr int kIOReturnError = -1, kIOReturnNotPermitted = -2, kIOReturnBadArgument = -3, kIOReturnNotReady = -4;
using kern_return_t = int;
static int IOConnectCallStructMethod(int connection, uint32_t selector, const void *, size_t,
                                    void *output, size_t *length) {
    assert(connection == Kernel && selector == ElanProviderBegin && *length == sizeof(NativeProviderReport));
    ++io->kernelCalls;
    io->fire("kernel");
    memset(output, 0, *length);
    static_cast<NativeProviderReport *>(output)->abi = 1;
    return 0;
}
struct ExecutableMappingDiagnostics {
    const char *outcome = "unused";
    uint32_t regions = 0, pathMatches = 0, headerMatches = 0;
    int queryBytes = 0, queryError = 0;
};
static constexpr const char *SettingsExecutable = "unused";
static bool stopSettings(int, bool &) { assert(false); return false; }
static bool resumeSettings() { assert(false); return false; }
static uint64_t executableMapping(int, const char *, ExecutableMappingDiagnostics *) { assert(false); return 0; }
static bool stopCoreAuth(int) { assert(false); return false; }
static bool retireCoreAuth(int) { assert(false); return false; }
static bool resumeCoreAuth() { assert(false); return false; }

#define poll mockPoll
#define read mockRead
#define write mockWrite
#define time mockTime
#define accept mockAccept
#define chown mockChown
#define chmod mockChmod
#define listen mockListen
#define setsockopt mockSetsockopt
#define shutdown mockShutdown
#define close mockClose
#define unlink mockUnlink
#include "native-broker-stop.h"
#include "native-broker-production.inc"
#undef poll
#undef read
#undef write
#undef time
#undef accept
#undef chown
#undef chmod
#undef listen
#undef setsockopt
#undef shutdown
#undef close
#undef unlink

static unsigned cases;
using Configure = std::function<void(TestIO &)>;
static void runCase(const std::string &name, bool managed, int expected, Configure configure = {}, Configure verify = {}) {
    TestIO state;
    io = &state;
    stopping = 0;
    if (configure) configure(state);
    int actual = runProductionServe(managed);
    if (actual != expected) {
        fprintf(stderr, "case=%s actual=%d expected=%d\n", name.c_str(), actual, expected);
        abort();
    }
    assert(state.recoverCalls == 1 && state.closedKernel == 1 && state.closedListener == 1);
    assert(state.socketRemovals == 1 && state.closedPeer == state.peerShutdowns);
    if (verify) verify(state);
    ++cases;
}

enum class Stop { Lease, Signal, Deadline, Data, InvalidLease };
static void trigger(TestIO &state, Stop stop) {
    switch (stop) {
        case Stop::Lease: state.endLease(); break;
        case Stop::Signal: stopSignal(SIGTERM); break;
        case Stop::Deadline: state.now += 960; break;
        case Stop::Data: state.leaseData(); state.endLease(); break;
        case Stop::InvalidLease: state.invalidateLease(); break;
    }
}

int main() {
    for (Stop stop : {Stop::Lease, Stop::Signal, Stop::Deadline, Stop::Data, Stop::InvalidLease}) {
        bool managed = stop != Stop::Deadline;
        int expected = stop == Stop::Data || stop == Stop::InvalidLease ? 1 : 0;
        for (const std::string point : {"before-accept", "listener-poll", "accept", "peer-poll", "request-read", "reply-write"}) {
            runCase("stop-" + std::to_string(static_cast<int>(stop)) + "-" + point, managed, expected,
                [=](TestIO &state) {
                    if (point == "before-accept" && stop != Stop::Deadline) trigger(state, stop);
                    state.on = [&, point, stop](const std::string &event) {
                        bool beforeDeadline = point == "before-accept" && stop == Stop::Deadline &&
                            event == "time" && state.events[event] == 2;
                        if ((event == point && state.events[event] == 1) || beforeDeadline) {
                            trigger(state, stop);
                            if (point == "listener-poll") state.listenerReady = 0;
                            if (point == "peer-poll") state.peerReady = 0;
                        }
                    };
                }, [=](TestIO &state) {
                    assert(state.kernelCalls == (point == "reply-write" ? 1 : 0));
                });
        }
    }
    runCase("boundary-eof-before-request", true, 0, [](TestIO &s) { s.input.clear(); });
    runCase("boundary-eof-after-reply", true, 0, {}, [](TestIO &s) {
        assert(s.kernelCalls == 1 && s.output.size() == sizeof(NativeProviderWireReply));
    });
    runCase("peer-hangup-boundary-eof", true, 0, [](TestIO &s) { s.input.clear(); s.peerEvents = POLLHUP; });
    runCase("fragmented-request-and-reply", true, 0, [](TestIO &s) {
        s.readChunk = 7; s.writeChunk = 5; s.readInterruptions = s.writeInterruptions = 2;
    }, [](TestIO &s) { assert(s.kernelCalls == 1 && s.output.size() == sizeof(NativeProviderWireReply)); });
    for (size_t count = 1; count < sizeof(NativeProviderWireRequest); ++count) {
        runCase("short-request-" + std::to_string(count), true, 1,
                [=](TestIO &s) { s.input.resize(count); }, [](TestIO &s) { assert(!s.kernelCalls); });
    }
    runCase("short-second-request", true, 1, [](TestIO &s) { s.input.resize(s.input.size() + 17); },
            [](TestIO &s) { assert(s.kernelCalls == 1); });
    for (int field = 0; field < 5; ++field) {
        runCase("malformed-before-lease-end-" + std::to_string(field), true, 1, [=](TestIO &s) {
            auto request = validRequest();
            if (field == 0) request.magic ^= 1;
            if (field == 1) request.reserved = 1;
            if (field == 2) request.selector = 0;
            if (field == 3) ++request.length;
            if (field == 4) s.rejectRequestPeer = true;
            s.request(request);
            s.on = [&](const std::string &event) { if (event == "request-read") s.endLease(); };
        }, [](TestIO &s) { assert(!s.kernelCalls); });
    }
    for (bool signal : {false, true}) {
        for (const std::string operation : {"listener-poll", "peer-poll", "accept", "request-read", "reply-write"}) {
            runCase("error-and-stop-" + operation + std::to_string(signal), true, 1, [=](TestIO &s) {
                if (operation == "listener-poll") s.listenerPollError = EIO;
                if (operation == "peer-poll") s.peerPollError = EIO;
                if (operation == "accept") s.acceptError = EMFILE;
                if (operation == "request-read") s.readError = ECONNRESET;
                if (operation == "reply-write") s.writeError = EPIPE;
                s.on = [&, operation, signal](const std::string &event) {
                    if (event == operation) trigger(s, signal ? Stop::Signal : Stop::Lease);
                };
            });
        }
    }
    for (int error : {EAGAIN, EIO, ECONNRESET, EBADF}) {
        runCase("read-error-" + std::to_string(error), true, 1, [=](TestIO &s) { s.readError = error; });
        runCase("partial-read-error-" + std::to_string(error), true, 1, [=](TestIO &s) {
            s.readChunk = 7; s.readErrorAt = 7; s.readError = error;
        });
    }
    runCase("partial-write-error", true, 1, [](TestIO &s) { s.writeChunk = 7; s.writeErrorAt = 7; s.writeError = EPIPE; });
    runCase("zero-write", true, 1, [](TestIO &s) { s.zeroWrite = true; });
    for (bool writing : {false, true}) {
        runCase("partial-transfer-signal-" + std::to_string(writing), true, 1, [=](TestIO &s) {
            s.readChunk = s.writeChunk = 7;
            s.on = [writing](const std::string &event) {
                if (event == (writing ? "reply-write" : "request-read")) stopSignal(SIGTERM);
            };
        });
    }
    for (const std::string operation : {"listener-poll", "peer-poll", "accept", "request-read"}) {
        for (bool signal : {false, true}) {
            runCase("interrupted-" + operation + std::to_string(signal), true, 0, [=](TestIO &s) {
                if (operation == "listener-poll") s.listenerPollError = EINTR;
                if (operation == "peer-poll") s.peerPollError = EINTR;
                if (operation == "accept") s.acceptError = EINTR;
                if (operation == "request-read") s.readInterruptions = 1;
                s.on = [operation, signal](const std::string &event) {
                    if (signal && event == operation) stopSignal(SIGTERM);
                };
            });
        }
    }
    for (short events : {short(POLLERR), short(POLLNVAL), short(POLLIN | POLLERR), short(0)}) {
        for (bool listener : {false, true}) {
            runCase("poll-events-" + std::to_string(events) + std::to_string(listener), true, 1, [=](TestIO &s) {
                if (listener) s.listenerEvents = events; else s.peerEvents = events;
                s.on = [&, listener](const std::string &event) {
                    if (event == (listener ? "listener-poll" : "peer-poll")) s.endLease();
                };
            });
        }
    }
    runCase("listener-hangup", true, 1, [](TestIO &s) { s.listenerEvents = POLLHUP; });
    for (const std::string failure : {"chown", "chmod", "listen", "receive-timeout", "send-timeout"}) {
        runCase("setup-failure-" + failure, true, 1, [=](TestIO &s) { s.setupFailure = failure; });
    }
    for (const std::string session : {"initial-session", "pinned-session"}) {
        runCase("session-stop-" + session, true, 0, [=](TestIO &s) { s.setupFailure = session; });
    }
    runCase("lease-poll-error", true, 1, [](TestIO &s) { s.leasePollError = EIO; });
    runCase("lease-poll-interrupted", true, 0, [](TestIO &s) { s.leasePollError = EINTR; s.endLease(); });
    runCase("lease-read-error", true, 1, [](TestIO &s) { s.leaseReadError = EIO; s.endLease(); });
    runCase("lease-read-interrupted", true, 0, [](TestIO &s) { s.leaseReadError = EINTR; s.endLease(); });
    runCase("lease-data-writer-open", true, 1, [](TestIO &s) { s.leaseData(); });
    runCase("recovery-error-after-normal-stop", true, 1, [](TestIO &s) { s.endLease(); s.recoverStatus = 1; });
    runCase("recovery-error-after-error", true, 1, [](TestIO &s) { s.readError = EIO; s.recoverStatus = 1; });
    runCase("stop-during-recovery-keeps-error", true, 1, [](TestIO &s) {
        s.readError = EIO;
        s.on = [&](const std::string &event) { if (event == "recover") { s.endLease(); stopSignal(SIGTERM); } };
    });
    assert(nativeBrokerControllerStop(-1) == NativeBrokerStop::Error);
    printf("BROKER_STOP production_loop=1 real_pipe_lease=1 cases=%u passed=1\n", cases);
}
