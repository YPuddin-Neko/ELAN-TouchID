#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <unistd.h>

@interface NSObject (EnrollmentAuthorizationResearch)
- (instancetype)initWithExternalizedContext:(NSData *)context;
- (NSData *)externalizedContext;
+ (const char *)acmPolicyForPolicy:(NSInteger)policy;
- (void)preflightPolicy:(const char *)policy parameters:(const void *)parameters parametersCount:(unsigned)count
    maxGlobalCredentialAge:(unsigned)age processRequirement:(void (^)(int, bool, const void *, NSError *))completion;
@end

int main(void) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        const char *root = "/System/Library/Frameworks/LocalAuthentication.framework/Support/";
        NSString *base = [NSString stringWithUTF8String:root];
        void *shared = dlopen([[base stringByAppendingString:@"SharedUtils.framework/Versions/A/SharedUtils"] UTF8String], RTLD_NOW | RTLD_LOCAL);
        void *daemon = dlopen([[base stringByAppendingString:@"DaemonUtils.framework/Versions/A/DaemonUtils"] UTF8String], RTLD_NOW | RTLD_LOCAL);
        unsigned (*type)(const void *) = daemon ? dlsym(daemon, "ACMRequirementGetType") : NULL;
        unsigned (*state)(const void *) = daemon ? dlsym(daemon, "ACMRequirementGetState") : NULL;
        Class helperClass = objc_getClass("LAACMHelper"), parameterClass = objc_getClass("LAManagedACMParameters");
        if (!shared || !type || !state || !helperClass || !parameterClass || getuid() != 501) return 2;
        const char *enrollment = NULL;
        for (NSInteger number = 1003; number <= 1027; number++) {
            const char *name = [helperClass acmPolicyForPolicy:number];
            if (name && !strcmp(name, "TouchIdEnrollment")) {
                enrollment = name;
                printf("ENROLL_AUTH_POLICY number=%ld name=%s\n", (long)number, name);
                break;
            }
        }
        if (!enrollment) return 3;
        __block int result = 0;
        for (unsigned user = 501; user <= 502; user++) {
            LAContext *owner = [LAContext new];
            @try {
                NSData *external = [owner externalizedContext];
                if (external.length != 16) { printf("ENROLL_AUTH_CREATE external_length=%lu\n", (unsigned long)external.length); return 4; }
                id helper = [[helperClass alloc] initWithExternalizedContext:external];
                id parameters = ((id (*)(id, SEL, unsigned))objc_msgSend)(parameterClass,
                    sel_registerName("acmParameterWithUserId:"), user);
                const void *bytes = ((const void *(*)(id, SEL))objc_msgSend)(parameters, sel_registerName("acmParameters"));
                unsigned count = ((unsigned (*)(id, SEL))objc_msgSend)(parameters, sel_registerName("count"));
                __block BOOL called = NO;
                [helper preflightPolicy:enrollment parameters:bytes parametersCount:count maxGlobalCredentialAge:0
                    processRequirement:^(int status, bool satisfied, const void *requirement, NSError *error) {
                        called = YES;
                        printf("ENROLL_AUTH_EMPTY user=%u status=%d satisfied=%d requirement_type=%u requirement_state=%u error=%ld\n",
                            user, status, satisfied, requirement ? type(requirement) : 0, requirement ? state(requirement) : 0, (long)error.code);
                        if (status || satisfied || error) result = 1;
                    }];
                if (!called) result = 1;
                helper = nil;
            } @finally {
                [owner invalidate];
                printf("ENROLL_AUTH_INVALIDATE user=%u\n", user);
            }
        }
        printf("ENROLL_AUTH_DONE status=%d credentials_created=0 own_contexts_only=1 authentication_requested=0\n", result);
        return result;
    }
}
