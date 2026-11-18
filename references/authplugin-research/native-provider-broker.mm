#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <IOKit/IOKitLib.h>
#include <mach/message.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <unistd.h>
#include <signal.h>
#include "native-controller-lease.h"
#include "native-broker-stop.h"
#include <errno.h>
#include <time.h>
#include "native-provider-wire.h"
#include "native-coreauth-control.h"
#include "native-settings-control.h"
#include "native-user-session-darwin.h"
#include <mach-o/dyld.h>

static volatile sig_atomic_t stopping;
static void stopSignal(int) { stopping = 1; }

static NSData *expectedWorkerIdentity(void) {
    const char *paths[] = {"/Library/ELANFingerprintNativeTest", NativeProviderWorker,
        "/Library/ELANFingerprintNativeTest/ELANNativeProvider.app/Contents/MacOS/ELANNativeProvider"};
    for (const char *path : paths) {
        struct stat info {};
        if (lstat(path, &info) || info.st_uid != 0 || (info.st_mode & 022) || S_ISLNK(info.st_mode)) return nil;
    }
    NSURL *url = [NSURL fileURLWithPath:@(NativeProviderWorker)];
    SecStaticCodeRef code = nullptr;
    if (SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code)) return nil;
    CFDictionaryRef info = nullptr;
    OSStatus status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, nullptr);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    NSDictionary *information = (__bridge NSDictionary *)info;
    NSNumber *flags = information[(__bridge NSString *)kSecCodeInfoFlags];
    NSDictionary *entitlements = information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    BOOL runtime = (flags.unsignedIntValue & kSecCodeSignatureRuntime) != 0;
    BOOL injectable = [entitlements[@"com.apple.security.cs.disable-library-validation"] boolValue] ||
                      [entitlements[@"com.apple.security.cs.allow-dyld-environment-variables"] boolValue] ||
                      [entitlements[@"com.apple.security.get-task-allow"] boolValue];
    NSData *identity = status || !runtime || injectable ? nil : [information[(__bridge NSString *)kSecCodeInfoUnique] copy];
    if (info) CFRelease(info);
    CFRelease(code);
    return identity;
}

static BOOL allowedPeer(int fd, NSData *expected) {
    uid_t user = 0; gid_t group = 0;
    if (getpeereid(fd, &user, &group) || user != 501) return NO;
    audit_token_t token {};
    socklen_t length = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) || length != sizeof(token)) return NO;
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:sizeof(token)]};
    SecCodeRef code = nullptr;
    OSStatus status = SecCodeCopyGuestWithAttributes(nullptr, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    CFDictionaryRef info = nullptr;
    if (!status) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, nullptr);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    NSData *identity = status ? nil : ((__bridge NSDictionary *)info)[(__bridge NSString *)kSecCodeInfoUnique];
    BOOL accepted = identity && [expected isEqualToData:identity];
    if (info) CFRelease(info);
    if (code) CFRelease(code);
    return accepted;
}

static int identitySelfTest(void) {
    SecCodeRef code = nullptr;
    CFDictionaryRef information = nullptr;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
    NSData *identity = status ? nil : ((__bridge NSDictionary *)information)[(__bridge NSString *)kSecCodeInfoUnique];
    int pair[2] = {-1, -1};
    BOOL own = NO, wrong = YES;
    if (identity.length && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
        own = allowedPeer(pair[0], identity);
        NSMutableData *other = [identity mutableCopy];
        static_cast<uint8_t *>(other.mutableBytes)[0] ^= 1;
        wrong = allowedPeer(pair[0], other);
    }
    if (pair[0] >= 0) close(pair[0]);
    if (pair[1] >= 0) close(pair[1]);
    if (information) CFRelease(information);
    if (code) CFRelease(code);
    printf("PROVIDER_PEER_TEST code_status=%d own_accepted=%d different_code_rejected=%d kernel_opened=0\n",
           (int)status, own, !wrong);
    return !status && own && !wrong ? 0 : 1;
}

enum class NativeBrokerTransfer { Complete, Stopped, EndOfStream, Error };

static NativeBrokerTransfer transfer(int fd, void *bytes, size_t length, bool writing) {
    uint8_t *cursor = static_cast<uint8_t *>(bytes);
    size_t remaining = length;
    while (remaining) {
        if (stopping) return remaining == length ? NativeBrokerTransfer::Stopped : NativeBrokerTransfer::Error;
        ssize_t count = writing ? write(fd, cursor, remaining) : read(fd, cursor, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (!count && !writing && remaining == length) return NativeBrokerTransfer::EndOfStream;
        if (count <= 0) return NativeBrokerTransfer::Error;
        cursor += count; remaining -= static_cast<size_t>(count);
    }
    return NativeBrokerTransfer::Complete;
}

static bool removeStaleSocket(void) {
    struct stat info {};
    if (lstat(NativeProviderSocket, &info)) return errno == ENOENT;
    if (!S_ISSOCK(info.st_mode) || info.st_uid != 501) return false;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_un address {}; address.sun_family = AF_UNIX; address.sun_len = sizeof(address);
    strlcpy(address.sun_path, NativeProviderSocket, sizeof(address.sun_path));
    int status = connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    int saved = errno; close(fd);
    return status && (saved == ECONNREFUSED || saved == ENOENT) &&
           (!unlink(NativeProviderSocket) || errno == ENOENT);
}

static int recoverSettings(io_connect_t connection, NativePlatformProcessReport &report) {
    size_t length = sizeof(report);
    kern_return_t call = IOConnectCallStructMethod(connection, ElanProviderSettingsRestore, nullptr, 0, &report, &length);
    bool valid = !call && length == sizeof(report) && report.abi == 1;
    if (valid && report.restartRequired && retireSettings(report.pid)) {
        length = sizeof(report);
        call = IOConnectCallStructMethod(connection, ElanProviderSettingsRestore, nullptr, 0, &report, &length);
        valid = !call && length == sizeof(report) && report.abi == 1;
    }
    bool restored = valid && !report.status && !report.attached && !report.restorePending && !report.restartRequired;
    SettingsTarget target {}; int journal = readSettingsJournal(target);
    if (restored && journal == 1) {
        restored = settingsGone(target) || resumeSettings();
        if (restored && unlink(SettingsJournal)) restored = false;
    } else if (journal < 0) restored = false;
    printf("PROVIDER_BROKER settings_cleanup_call=0x%x status=%d restored=%d\n", call, report.status, restored);
    return restored ? 0 : 1;
}

static int settingsControlSelfTest(void) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    SettingsTarget target {};
    bool denied = !settingsIdentity(getpid(), target);
    ExecutableMappingDiagnostics trace {}, missing {};
    uint64_t mapping = proc_pidpath(getpid(), path, sizeof(path)) > 0 ? executableMapping(getpid(), path, &trace) : 0;
    bool found = mapping && mapping == reinterpret_cast<uint64_t>(_dyld_get_image_header(0));
    bool traced = !strcmp(trace.outcome, "found") && trace.regions && trace.pathMatches && trace.headerMatches;
    bool notFound = !executableMapping(getpid(), "/__elan_nonexistent_executable__", &missing) &&
                    strcmp(missing.outcome, "found") && !missing.pathMatches && !missing.headerMatches;
    printf("SETTINGS_CONTROL_TEST own_image_found=%d ordinary_process_rejected=%d mapping_diagnostics=%d missing_path_rejected=%d kernel_opened=0 processes_stopped=0\n",
           found, denied, traced, notFound);
    return found && denied && traced && notFound ? 0 : 1;
}

static int recoverProvider(io_connect_t connection, NativeProviderReport *final = nullptr) {
    NativePlatformProcessReport settings {};
    int settingsStatus = recoverSettings(connection, settings);
    NativeProviderReport report {};
    size_t length = sizeof(report);
    kern_return_t status = IOConnectCallStructMethod(connection, ElanProviderEnd, nullptr, 0, &report, &length);
    NativePlatformProcessReport platform {};
    size_t platformLength = sizeof(platform);
    kern_return_t platformStatus = IOConnectCallStructMethod(connection, ElanProviderPlatformRestore,
        nullptr, 0, &platform, &platformLength);
    bool platformValid = !platformStatus && platformLength == sizeof(platform) && platform.abi == 1;
    if (platformValid && platform.restartRequired && retireCoreAuth(platform.pid)) {
        length = sizeof(report);
        status = IOConnectCallStructMethod(connection, ElanProviderEnd, nullptr, 0, &report, &length);
    }
    bool restored = platformValid && !status && length == sizeof(report) && report.abi == 1 && !report.operationStatus &&
                    !report.restoreStatus && !report.restorePending && !report.quarantinedContext && !report.active &&
                    report.availability == 0;
    {
        CoreAuthJournalLock journalLock;
        CoreAuthTarget target {};
        int journal = readCoreAuthJournalLocked(journalLock, target);
        if (restored && platformValid && journal == 1) {
            restored = coreAuthGone(target) || resumeCoreAuthLocked(journalLock);
            CoreAuthTarget latest {};
            if (restored && (readCoreAuthJournalLocked(journalLock, latest) != 1 ||
                memcmp(&target, &latest, sizeof(target)) || unlink(CoreAuthJournal))) restored = false;
        } else if (journal < 0) restored = false;
    }
    restored = restored && !settingsStatus;
    if (!restored && !report.restoreStatus) report.restoreStatus = -33008;
    if (final) *final = report;
    printf("PROVIDER_BROKER cleanup_call=0x%x operation=%d restore=%d pending=%u context_pending=%u restored=%d\n",
           status, report.operationStatus, report.restoreStatus, report.restorePending, report.quarantinedContext, restored);
    return restored ? 0 : 1;
}

static bool brokerSessionCurrent(bool pinned) {
    uint32_t user = UINT32_MAX;
    bool known = nativeConsoleUser(&user);
    if (!nativeConsoleUserAllowed(known, user)) {
        puts("PROVIDER_BROKER session_stopped=console-owner"); return false;
    }
    if (pinned) {
        CoreAuthTarget target {};
        int journal = readCoreAuthJournal(target);
        if (journal < 0 || (journal == 1 && !sameCoreAuth(target))) {
            puts("PROVIDER_BROKER session_stopped=coreauth-lifetime"); return false;
        }
    }
    return true;
}

static NativeBrokerStop brokerStop(bool managed, time_t deadline) {
    if (managed) {
        NativeBrokerStop lease = nativeBrokerControllerStop(STDIN_FILENO);
        if (lease != NativeBrokerStop::Running) return lease;
    }
    return stopping || (!managed && time(nullptr) >= deadline) ? NativeBrokerStop::Normal : NativeBrokerStop::Running;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "--peer-self-test")) return identitySelfTest();
        if (argc == 2 && !strcmp(argv[1], "--settings-self-test")) return settingsControlSelfTest();
        if (argc == 2 && !strcmp(argv[1], "--check-controller-lease")) {
            setbuf(stdout, nullptr);
            if (!nativeControllerLeaseValid(STDIN_FILENO)) return 2;
            puts("CONTROLLER_LEASE ready=1 kernel_opened=0");
            time_t until = time(nullptr) + 10;
            while (nativeControllerLeaseAlive(STDIN_FILENO) && time(nullptr) < until) usleep(10000);
            bool ended = !nativeControllerLeaseAlive(STDIN_FILENO);
            printf("CONTROLLER_LEASE ended=%d kernel_opened=0\n", ended);
            return ended ? 0 : 1;
        }
        bool connectionRecoveryEnabled = argc == 2 && !strcmp(argv[1], "--serve-managed-settings-recovery");
        bool managed = connectionRecoveryEnabled || (argc == 2 && !strcmp(argv[1], "--serve-managed"));
        if (argc != 2 || (!managed && !connectionRecoveryEnabled && strcmp(argv[1], "--serve") && strcmp(argv[1], "--recover"))) return 2;
        if (managed && (!nativeControllerLeaseValid(STDIN_FILENO) || nativeBrokerControllerStop(STDIN_FILENO) != NativeBrokerStop::Running)) return 2;
        if (geteuid() != 0) { puts("PROVIDER_BROKER root_required=1"); return 3; }
        setbuf(stdout, nullptr);
        signal(SIGINT, stopSignal); signal(SIGTERM, stopSignal); signal(SIGPIPE, SIG_IGN);
        if (strcmp(argv[1], "--recover") && !brokerSessionCurrent(false)) return 9;
        io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(ELAN_NATIVE_PROBE_SERVICE));
        if (!service) return 4;
        io_connect_t connection = IO_OBJECT_NULL;
        kern_return_t open = IOServiceOpen(service, mach_task_self(), 0, &connection);
        IOObjectRelease(service);
        if (open) { printf("PROVIDER_BROKER open=0x%x\n", open); return 5; }
        if (!strcmp(argv[1], "--recover")) {
            int result = recoverProvider(connection);
            if (!result && !removeStaleSocket()) result = 1;
            IOServiceClose(connection); return result;
        }
        NSData *expected = expectedWorkerIdentity();
        if (!expected.length) { puts("PROVIDER_BROKER worker_install_invalid=1"); IOServiceClose(connection); return 6; }
        int listener = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener < 0) { IOServiceClose(connection); return 7; }
        sockaddr_un address {};
        address.sun_family = AF_UNIX;
        strlcpy(address.sun_path, NativeProviderSocket, sizeof(address.sun_path));
        address.sun_len = sizeof(address);
        mode_t previousMask = umask(077);
        int bound = bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address));
        umask(previousMask);
        if (bound) { close(listener); IOServiceClose(connection); return 8; }
        int result = 1, peer = -1;
        do {
            if (chown(NativeProviderSocket, 501, 20) || chmod(NativeProviderSocket, 0600) || listen(listener, 2)) break;
            printf("PROVIDER_BROKER ready=1 lifetime_seconds=%d controller_bound=%d\n", managed ? 0 : 960, managed);
            time_t deadline = time(nullptr) + 960;
            while (peer < 0) {
                NativeBrokerStop stop = brokerStop(managed, deadline);
                if (stop != NativeBrokerStop::Running) { result = stop == NativeBrokerStop::Normal ? 0 : 1; break; }
                if (!brokerSessionCurrent(false)) { result = 0; break; }
                pollfd descriptor {listener, POLLIN, 0};
                int ready = poll(&descriptor, 1, 250);
                if (ready < 0 && errno == EINTR) continue;
                if (ready < 0) break;
                if (!ready) continue;
                if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) || !(descriptor.revents & POLLIN)) break;
                int candidate = accept(listener, nullptr, nullptr);
                if (candidate < 0 && errno == EINTR) continue;
                if (candidate < 0) break;
                if (!allowedPeer(candidate, expected)) { close(candidate); puts("PROVIDER_BROKER rejected_peer=1"); continue; }
                peer = candidate;
            }
            if (peer < 0) break;
            timeval timeout {3, 0};
            if (setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
                setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) break;
            puts("PROVIDER_BROKER verified_worker=1");
            time_t nextSessionCheck = 0;
            while (true) {
                NativeBrokerStop stop = brokerStop(managed, deadline);
                if (stop != NativeBrokerStop::Running) { result = stop == NativeBrokerStop::Normal ? 0 : 1; break; }
                if (time(nullptr) >= nextSessionCheck) {
                    if (!brokerSessionCurrent(true)) { result = 0; break; }
                    nextSessionCheck = time(nullptr) + 1;
                }
                pollfd descriptor {peer, POLLIN, 0};
                int ready = poll(&descriptor, 1, 250);
                if (ready < 0 && errno == EINTR) continue;
                if (ready < 0) break;
                if (!ready) continue;
                if ((descriptor.revents & (POLLERR | POLLNVAL)) || !(descriptor.revents & (POLLIN | POLLHUP))) break;
                NativeProviderWireRequest request {};
                NativeBrokerTransfer received = transfer(peer, &request, sizeof(request), false);
                if (received != NativeBrokerTransfer::Complete) { result = received == NativeBrokerTransfer::Error ? 1 : 0; break; }
                if (!allowedPeer(peer, expected) || request.magic != NativeProviderWireMagic || request.reserved ||
                    !nativeProviderIsSelector(request.selector) ||
                    request.length != nativeProviderInputSize(request.selector)) break;
                stop = brokerStop(managed, deadline);
                if (stop != NativeBrokerStop::Running) { result = stop == NativeBrokerStop::Normal ? 0 : 1; break; }
                if (request.selector != ElanProviderEnd && request.selector != ElanProviderSettingsRestore &&
                    !brokerSessionCurrent(true)) { result = 0; break; }
                NativeProviderWireReply reply {};
                reply.magic = NativeProviderWireMagic;
                size_t output = nativeProviderOutputSize(request.selector);
                if (request.selector == ElanProviderEnd) {
                    recoverProvider(connection, &reply.data.provider);
                } else if (request.selector == ElanProviderSettingsRestore) {
                    if (recoverSettings(connection, reply.data.platform)) reply.callStatus = kIOReturnError;
                } else if (request.selector == ElanProviderSettingsInspect || request.selector == ElanProviderSettingsRecover) {
                    // The diagnostic runs only inside the broker-owned stopped-process window.
                    reply.callStatus = kIOReturnNotPermitted;
                } else if (request.selector == ElanProviderSettingsEnable) {
                    auto &settings = request.data.settings;
                    bool ownedAttempt = false;
                    if (settings.image || settings.abi != 1 || settings.user != 501 || settings.reserved || !stopSettings(settings.pid, ownedAttempt)) {
                        reply.callStatus = kIOReturnNotPermitted;
                        printf("PROVIDER_BROKER settings_stage=admission call=0x%x owned_attempt=%d\n",
                               reply.callStatus, ownedAttempt);
                        fflush(stdout);
                        if (ownedAttempt) {
                            NativePlatformProcessReport restored {};
                            if (recoverSettings(connection, restored)) reply.callStatus = kIOReturnError;
                        }
                    } else {
                        ExecutableMappingDiagnostics mapping {};
                        settings.image = executableMapping(settings.pid, SettingsExecutable, &mapping);
                        // Record only counters and protocol status, never process addresses or biometric data.
                        printf("PROVIDER_BROKER settings_stage=mapping outcome=%s regions=%u path_matches=%u header_matches=%u query_bytes=%d query_errno=%d found=%d\n",
                               mapping.outcome, mapping.regions, mapping.pathMatches, mapping.headerMatches,
                               mapping.queryBytes, mapping.queryError, settings.image != 0);
                        NativeSettingsInspectionReport inspection {};
                        size_t inspectionSize = sizeof(inspection);
                        kern_return_t inspectionCall = settings.image ? IOConnectCallStructMethod(connection,
                            ElanProviderSettingsInspect, &settings, sizeof(settings), &inspection, &inspectionSize) : kIOReturnBadArgument;
                        bool recoveryRequested = nativeSettingsInspectionAllowsRecovery(inspectionCall, inspectionSize, inspection, connectionRecoveryEnabled);
                        bool inspectionAllowed = nativeSettingsInspectionAllowsEnable(inspectionCall, inspectionSize, inspection) || recoveryRequested;
                        printf("PROVIDER_BROKER settings_stage=connection_inspection call=0x%x status=%d image_matched=%u observation=%u stage=%u allowed=%d\n",
                               inspectionCall, inspection.status, inspection.imageMatched, inspection.observation, inspection.stage, inspectionAllowed);
                        // Stop before mutation if the connection was already initialized or could not be verified.
                        NativeSettingsRecoveryReport recoveryReport {};
                        size_t recoverySize = sizeof(recoveryReport);
                        reply.callStatus = inspectionAllowed ? IOConnectCallStructMethod(connection, recoveryRequested ? ElanProviderSettingsRecover : request.selector,
                            &request.data, request.length, recoveryRequested ? static_cast<void *>(&recoveryReport) : static_cast<void *>(&reply.data),
                            recoveryRequested ? &recoverySize : &output) : kIOReturnNotReady;
                        if (recoveryRequested) {
                            bool valid = nativeSettingsRecoveryReportValid(reply.callStatus, recoverySize, recoveryReport);
                            if (valid) reply.data.platform = recoveryReport.platform;
                            else if (!reply.callStatus) reply.callStatus = kIOReturnBadArgument;
                            // Worker selector 13 keeps its original 32-byte reply.
                            output = sizeof(NativePlatformProcessReport);
                            bool confirmed = valid && !recoveryReport.transactionStatus && recoveryReport.platform.restartRequired;
                            int recoveryStatus = reply.callStatus ? static_cast<int32_t>(reply.callStatus) : recoveryReport.transactionStatus;
                            if (valid)
                                printf("PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=%d modified=%s phase=%u rollback_status=%d\n",
                                       recoveryStatus, confirmed ? "1" : "unknown", recoveryReport.phase, recoveryReport.rollbackStatus);
                            else
                                printf("PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=%d modified=unknown\n", recoveryStatus);
                        }
                        printf("PROVIDER_BROKER settings_stage=%s call=0x%x input_bytes=%u expected_input=%zu output_bytes=%zu expected_output=%zu reply_abi=%u operation_status=%d\n",
                               settings.image ? "kernel" : "mapping_rejected", reply.callStatus,
                               request.length, sizeof(NativeSettingsProcessRequest), output,
                               sizeof(NativePlatformProcessReport), reply.data.platform.abi, reply.data.platform.status);
                        fflush(stdout);
                        bool enabled = !reply.callStatus && output == sizeof(NativePlatformProcessReport) &&
                            reply.data.platform.abi == 1 && !reply.data.platform.status && reply.data.platform.restartRequired;
                        if (enabled) {
                            if (!resumeSettings()) {
                                reply.callStatus = kIOReturnError;
                                NativePlatformProcessReport restored {};
                                recoverSettings(connection, restored);
                            }
                        } else {
                            NativePlatformProcessReport restored {};
                            if (recoverSettings(connection, restored)) reply.callStatus = kIOReturnError;
                        }
                    }
                } else if (request.selector == ElanProviderPlatformEnable) {
                    if (!stopCoreAuth(request.data.platform.pid)) reply.callStatus = kIOReturnNotPermitted;
                    else {
                        reply.callStatus = IOConnectCallStructMethod(connection, request.selector,
                            &request.data, request.length, &reply.data, &output);
                        bool changed = !reply.callStatus && output == sizeof(NativePlatformProcessReport) &&
                            reply.data.platform.abi == 1 && reply.data.platform.restartRequired;
                        if (changed && reply.data.platform.status) {
                            if (!retireCoreAuth(reply.data.platform.pid)) reply.callStatus = kIOReturnError;
                        } else if (!resumeCoreAuth()) reply.callStatus = kIOReturnError;
                    }
                } else reply.callStatus = IOConnectCallStructMethod(connection, request.selector,
                    request.length ? &request.data : nullptr, request.length, &reply.data, &output);
                reply.length = static_cast<uint32_t>(output);
                memset(&request.data, 0, sizeof(request.data));
                printf("PROVIDER_BROKER selector=%u call=0x%x\n", request.selector, reply.callStatus);
                NativeBrokerTransfer sent = transfer(peer, &reply, sizeof(reply), true);
                if (sent != NativeBrokerTransfer::Complete) { result = sent == NativeBrokerTransfer::Error ? 1 : 0; break; }
            }
        } while (false);
        if (peer >= 0) { shutdown(peer, SHUT_RDWR); close(peer); }
        close(listener);
        unlink(NativeProviderSocket);
        if (recoverProvider(connection)) result = 1;
        IOServiceClose(connection);
        printf("PROVIDER_BROKER_DONE status=%d\n", result);
        return result;
    }
}
