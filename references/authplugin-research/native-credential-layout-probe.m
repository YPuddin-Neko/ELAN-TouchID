#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <malloc/malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        void *framework = dlopen("/System/Library/Frameworks/LocalAuthentication.framework/Support/DaemonUtils.framework/Versions/A/DaemonUtils", RTLD_LAZY | RTLD_LOCAL);
        int (*create)(unsigned, void **) = framework ? dlsym(framework, "ACMCredentialCreate") : NULL;
        void (*destroy)(void *) = framework ? dlsym(framework, "ACMCredentialDelete") : NULL;
        unsigned (*getType)(const void *) = framework ? dlsym(framework, "ACMCredentialGetType") : NULL;
        int (*setProperty)(void *, unsigned, const void *, size_t) = framework ? dlsym(framework, "ACMCredentialSetProperty") : NULL;
        int (*getProperty)(const void *, unsigned, const void **, size_t *) = framework ? dlsym(framework, "ACMCredentialGetPropertyData") : NULL;
        if (!create || !destroy || !getType || !setProperty || !getProperty) {
            puts("CREDENTIAL_LAYOUT missing_entrypoint=1");
            return 2;
        }
        void *credential = NULL;
        int status = create(3, &credential);
        if (status || !credential) {
            printf("CREDENTIAL_LAYOUT create_status=%d created=%d\n", status, credential != NULL);
            return 3;
        }
        int result = 1;
        @try {
            size_t allocation = malloc_size(credential);
            unsigned type = getType(credential);
            printf("CREDENTIAL_LAYOUT create_status=%d type=%u allocation=%zu\n", status, type, allocation);
            if (type != 3 || allocation < 0x151) return 4;
            uint32_t dataLength = 0;
            memcpy(&dataLength, (const uint8_t *)credential + 0x1c, sizeof(dataLength));
            printf("CREDENTIAL_LAYOUT data_length=%u\n", dataLength);
            if (dataLength != 0x131) return 5;
            uint32_t user = (uint32_t)getuid();
            uint32_t fixtureFlags = 4;
            const uint8_t fixtureID[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                           0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f};
            struct { unsigned property; const void *value; size_t length; size_t expectedOffset; } cases[] = {
                {5, &user, sizeof(user), 0x0c},
                {101, &fixtureFlags, sizeof(fixtureFlags), 0x20},
                {100, fixtureID, sizeof(fixtureID), 0x68}
            };
            for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                const void *readback = NULL;
                size_t length = 0;
                int setStatus = setProperty(credential, cases[i].property, cases[i].value, cases[i].length);
                int getStatus = getProperty(credential, cases[i].property, &readback, &length);
                uintptr_t base = (uintptr_t)credential, address = (uintptr_t)readback;
                BOOL inAllocation = address >= base && address - base <= allocation && length <= allocation - (address - base);
                size_t offset = inAllocation ? address - base : SIZE_MAX;
                BOOL equal = !setStatus && !getStatus && inAllocation && length == cases[i].length &&
                             !memcmp(readback, cases[i].value, length);
                BOOL passed = equal && offset == cases[i].expectedOffset;
                printf("CREDENTIAL_LAYOUT property=%u set=%d get=%d length=%zu offset=%zu equal=%d pass=%d\n",
                       cases[i].property, setStatus, getStatus, length, offset, equal, passed);
                if (!passed) return 6;
            }
            result = 0;
        } @finally {
            destroy(credential);
            puts("CREDENTIAL_LAYOUT cleanup=1 contexts_created=0 credentials_submitted=0");
        }
        printf("CREDENTIAL_LAYOUT_DONE status=%d\n", result);
        return result;
    }
}
