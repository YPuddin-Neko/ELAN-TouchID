#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
    uint32_t type;
    const void *value;
    uint32_t length;
} NativeACMParameter;
_Static_assert(sizeof(NativeACMParameter) == 24, "x86_64 ACM parameter size");
_Static_assert(offsetof(NativeACMParameter, value) == 8, "ACM value offset");

int main(void) {
    @autoreleasepool {
        if (!dlopen("/System/Library/Frameworks/LocalAuthentication.framework/Support/SharedUtils.framework/Versions/A/SharedUtils", RTLD_LAZY | RTLD_LOCAL)) return 2;
        Class cls = NSClassFromString(@"LAManagedACMParameters");
        SEL create = sel_registerName("acmParameterWithUserId:");
        SEL countSelector = sel_registerName("count");
        SEL dataSelector = sel_registerName("acmParameters");
        if (!cls || !class_getClassMethod(cls, create)) return 3;
        Method method = class_getInstanceMethod(cls, dataSelector);
        if (!method) return 4;
        printf("ACM_PARAMETER_ABI method=%s\n", method_getTypeEncoding(method));
        char *returnType = method_copyReturnType(method);
        BOOL layout = returnType && (!strcmp(returnType, "^{?=I^vI}") || !strcmp(returnType, "r^{?=I^vI}"));
        free(returnType);
        if (!layout || method_getNumberOfArguments(method) != 2) return 5;
        id parameters = ((id (*)(id, SEL, unsigned))objc_msgSend)(cls, create, (unsigned)getuid());
        unsigned count = ((unsigned (*)(id, SEL))objc_msgSend)(parameters, countSelector);
        const NativeACMParameter *data = ((const NativeACMParameter *(*)(id, SEL))objc_msgSend)(parameters, dataSelector);
        if (count != 1 || !data || !data->value || data->length != sizeof(uint32_t)) return 6;
        uint32_t user = 0;
        memcpy(&user, data->value, sizeof(user));
        BOOL equal = user == getuid();
        printf("ACM_PARAMETER type=%u length=%u user_matches=%d size=%zu\n", data->type, data->length, equal, sizeof(*data));
        puts("ACM_PARAMETER_DONE contexts_created=0 credentials_submitted=0");
        return equal ? 0 : 7;
    }
}
