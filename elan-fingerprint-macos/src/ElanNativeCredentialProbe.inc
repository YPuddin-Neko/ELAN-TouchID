#include <dlfcn.h>

@interface NSObject (ElanCredentialResearch)
-(instancetype)initWithACMContext:(void *)context;
+(const char *)acmPolicyForPolicy:(NSInteger)policy;
-(void)preflightPolicy:(const char *)policy parameters:(const void *)parameters
      parametersCount:(unsigned)count maxGlobalCredentialAge:(unsigned)age
   processRequirement:(void (^)(int,bool,const void *,NSError *))completion;
@end

static void elan_native_credential_probe(void) {
    syslog(LOG_NOTICE,"ElanNativeProbe: host=%s uid=%u",NSProcessInfo.processInfo.processName.UTF8String,geteuid());
    if(geteuid()!=0){syslog(LOG_NOTICE,"ElanNativeProbe: privileged host required");return;}
    const char *root="/System/Library/Frameworks/LocalAuthentication.framework/Support/";
    NSString *directory=[NSString stringWithUTF8String:root];
    void *shared=dlopen([[directory stringByAppendingString:@"SharedUtils.framework/Versions/A/SharedUtils"] UTF8String],RTLD_LAZY|RTLD_LOCAL);
    void *daemon=dlopen([[directory stringByAppendingString:@"DaemonUtils.framework/Versions/A/DaemonUtils"] UTF8String],RTLD_LAZY|RTLD_LOCAL);
    int (*createContext)(void **)=daemon?dlsym(daemon,"ACMContextCreate"):NULL;
    int (*deleteContext)(void *,bool)=daemon?dlsym(daemon,"ACMContextDelete"):NULL;
    unsigned (*requirementType)(const void *)=daemon?dlsym(daemon,"ACMRequirementGetType"):NULL;
    unsigned (*requirementState)(const void *)=daemon?dlsym(daemon,"ACMRequirementGetState"):NULL;
    Class helperClass=NSClassFromString(@"LAACMHelper");
    if(!shared || !helperClass || !createContext || !deleteContext || !requirementType || !requirementState) {
        syslog(LOG_ERR,"ElanNativeProbe: missing helper or entrypoint");return;
    }
    void *context=NULL;
    int status=createContext(&context);
    syslog(LOG_NOTICE,"ElanNativeProbe: context created=%d status=%d",context!=NULL,status);
    if(status || !context)return;
    @try {
        id helper=[[helperClass alloc] initWithACMContext:context];
        const char *policy=[helperClass acmPolicyForPolicy:1];
        syslog(LOG_NOTICE,"ElanNativeProbe: policy=%s",policy?policy:"missing");
        if(helper && policy) {
            __block BOOL replied=NO;
            [helper preflightPolicy:policy parameters:NULL parametersCount:0 maxGlobalCredentialAge:0
                processRequirement:^(int result,bool satisfied,const void *requirement,NSError *error) {
                    replied=YES;
                    syslog(LOG_NOTICE,"ElanNativeProbe: preflight status=%d satisfied=%d requirement_type=%u requirement_state=%u error_domain=%s error=%ld",
                           result,satisfied,requirementType(requirement),requirementState(requirement),
                           error?error.domain.UTF8String:"none",(long)error.code);
                }];
            syslog(LOG_NOTICE,"ElanNativeProbe: callback returned=%d",replied);
        }
        helper=nil;
    } @finally {
        syslog(LOG_NOTICE,"ElanNativeProbe: context deleted status=%d",deleteContext(context,true));
    }
}
