#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int elanProviderConnect(void);
int elanProviderBegin(int fd, const uint8_t identity[16]);
int elanProviderBeginCatalog(int fd, const uint8_t *identities, uint32_t count);
int elanProviderReplaceCatalog(int fd, uint64_t sequence, const uint8_t *identities, uint32_t count);
int elanProviderAuthorizeEnrollment(int fd, uint64_t sequence, const uint8_t context[16]);
int elanProviderMatch(int fd, uint64_t sequence, const uint8_t identity[16], const uint8_t context[16], bool matched);
int elanProviderPlatform(int fd, int32_t pid, uint64_t function,
                         uint64_t instanceGetter, uint64_t faultGetter,
                         uint64_t permanentGetter, uint64_t helperClass);
int elanProviderEnd(int fd);
int elanProviderSettings(int fd, int32_t pid, uint64_t function);
int elanProviderSettingsRestore(int fd);
#ifdef __cplusplus
}
#endif
