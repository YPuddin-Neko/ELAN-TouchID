#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <signal.h>

static volatile sig_atomic_t interrupted;
static void stopTest(int signal) { interrupted = 1; }

int main(int argc, char **argv) {
    @autoreleasepool {
        BOOL authenticate = argc == 2 && !strcmp(argv[1], "--authenticate");
        if (argc != 2 || (!authenticate && strcmp(argv[1], "--capability"))) return 2;
        setbuf(stdout, NULL);
        signal(SIGINT, stopTest); signal(SIGTERM, stopTest);
        LAContext *context = [LAContext new];
        context.localizedFallbackTitle = @"";
        context.localizedCancelTitle = @"取消";
        __block BOOL finished = NO;
        __block int result = 1;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                NSError *error = nil;
                BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
                printf("SYSTEM_BIOMETRY available=%d type=%ld error=%ld\n", available, (long)context.biometryType, (long)error.code);
                if (!available || !authenticate) {
                    dispatch_async(dispatch_get_main_queue(), ^{ result = available ? 0 : 1; finished = YES; });
                    return;
                }
                [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                        localizedReason:@"验证 ELAN 指纹"
                                  reply:^(BOOL success, NSError *authenticationError) {
                    printf("SYSTEM_AUTHENTICATION success=%d error=%ld\n", success, (long)authenticationError.code);
                    dispatch_async(dispatch_get_main_queue(), ^{ result = success ? 0 : 1; finished = YES; });
                }];
            }
        });
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:90];
        while (!finished && !interrupted && deadline.timeIntervalSinceNow > 0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        [context invalidate];
        if (!finished) { result = 124; puts("SYSTEM_AUTHENTICATION interrupted_or_timed_out=1"); }
        puts("SYSTEM_AUTHENTICATION_CONTEXT invalidated=1");
        return result;
    }
}
