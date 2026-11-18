#pragma once
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static constexpr const char *CoreAuthJournalLockPath = "/private/var/run/elan-native-provider-501.state.lock";
// Cooperative serialization for rebuilt participants only. Never unlink this
// lock inode. Legacy binaries and arbitrary root pathname replacement are not
// covered; exclude old controllers/brokers before a supported trial.
class CoreAuthJournalLock {
    int descriptor = -1;
    int failure = 0;
public:
    // Overrides are for isolated host fixtures; production uses the fixed path/UID.
    explicit CoreAuthJournalLock(const char *path = CoreAuthJournalLockPath, uid_t owner = 0) {
        descriptor = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
        if (descriptor < 0) { failure = errno; return; }
        struct stat opened {}, named {};
        if (fstat(descriptor, &opened)) failure = errno;
        else if (!S_ISREG(opened.st_mode) || opened.st_uid != owner ||
                 (opened.st_mode & 07777) != 0600 || opened.st_nlink != 1) failure = EINVAL;
        else if (flock(descriptor, LOCK_EX | LOCK_NB)) failure = errno;
        else if (lstat(path, &named)) failure = errno;
        else if (opened.st_dev != named.st_dev || opened.st_ino != named.st_ino) failure = ESTALE;
        if (failure) { close(descriptor); descriptor = -1; }
    }
    ~CoreAuthJournalLock() { if (descriptor >= 0) close(descriptor); }
    bool held() const { return descriptor >= 0; }
    int error() const { return failure; }
    CoreAuthJournalLock(const CoreAuthJournalLock &) = delete;
    CoreAuthJournalLock &operator=(const CoreAuthJournalLock &) = delete;
};
