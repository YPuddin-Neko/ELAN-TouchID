#define ELAN_NO_APP_MAIN 1
#include "../../elan-fingerprint-macos/src/ElanUnlock.m"
#include <dlfcn.h>
#include <objc/message.h>

@interface NSObject (ElanACMResearch)
- (instancetype)initWithACMContext:(void *)context;
+ (const char *)acmPolicyForPolicy:(NSInteger)policy;
- (void)preflightPolicy:(const char *)policy parameters:(const void *)parameters
       parametersCount:(unsigned)count maxGlobalCredentialAge:(unsigned)age
    processRequirement:(void (^)(int,bool,const void *,NSError *))completion;
- (BOOL)addCredential:(unsigned)type scope:(unsigned)scope error:(NSError **)error;
@end

static BOOL inspectEmptyOrMatchedContext(id helper,id parameters,const char *phase,BOOL *satisfied) {
    Class cls=NSClassFromString(@"LAACMHelper");
    const char *policy=[cls acmPolicyForPolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics];
    const void *bytes=((const void *(*)(id,SEL))objc_msgSend)(parameters,sel_registerName("acmParameters"));
    unsigned count=((unsigned(*)(id,SEL))objc_msgSend)(parameters,sel_registerName("count"));
    __block BOOL completed=NO,ok=NO,accepted=NO;
    [helper preflightPolicy:policy parameters:bytes parametersCount:count maxGlobalCredentialAge:0
        processRequirement:^(int status,bool value,const void *requirement,NSError *error) {
            completed=YES;ok=status==0 && error==nil;accepted=value;
            printf("ELAN_ACM_PREFLIGHT phase=%s status=%d satisfied=%d error=%ld\n",phase,status,value,(long)error.code);
        }];
    *satisfied=accepted;
    return completed && ok;
}

static int elanCredentialStudy(void) {
    signal(SIGINT,interrupt);signal(SIGTERM,interrupt);cancelled=0;
    void *shared=dlopen("/System/Library/Frameworks/LocalAuthentication.framework/Support/SharedUtils.framework/Versions/A/SharedUtils",RTLD_LAZY|RTLD_LOCAL);
    void *daemon=dlopen("/System/Library/Frameworks/LocalAuthentication.framework/Support/DaemonUtils.framework/Versions/A/DaemonUtils",RTLD_LAZY|RTLD_LOCAL);
    int (*createContext)(void **)=daemon?dlsym(daemon,"ACMContextCreate"):NULL;
    int (*deleteContext)(void *,bool)=daemon?dlsym(daemon,"ACMContextDelete"):NULL;
    Class helperClass=NSClassFromString(@"LAACMHelper"),parameterClass=NSClassFromString(@"LAManagedACMParameters");
    if(!shared || !helperClass || !parameterClass || !createContext || !deleteContext)return 4;
    id parameters=((id(*)(id,SEL,unsigned))objc_msgSend)(parameterClass,sel_registerName("acmParameterWithUserId:"),getuid());
    if(!parameters)return 4;
    puts("ELAN 系统凭据接口测试：沿用已录入指纹，共按两次。按 Control+C 可退出。");
    puts("这次使用终端观察接口结果；不会打开认证窗口，也不会解锁系统。");
    NSMutableData *stored=nil;
    int result=1;
    @try {
        if(!pause_prompt("先移开手指，按回车开始。"))return 1;
        if(!open_sensor(&sensor))return 2;
        stored=loadSecret(@"fingerprints-v1",YES);
        if(!unpackPrints(stored)){puts("无法读取已录入指纹；请允许此测试程序访问指纹钥匙串项。");return 3;}
        wipe(stored.mutableBytes,stored.length);stored=nil;
        printf("ELAN_ACM templates=%d threshold=%d uid=%u\n",printCount,ELANPRESS_MATCH_MIN_PAIRS,getuid());
        for(int step=0;step<2 && !cancelled;step++) {
            puts(step==0?"1/2：用另一根未录入的手指。":"2/2：用已录入的手指，指腹保持中心位置。");
            if(!pause_prompt("先松开手指，准备好后按回车，再按采集提示轻放。"))break;
            void *context=NULL;
            int status=createContext(&context);
            printf("ELAN_ACM_CONTEXT step=%d created=%d status=%d\n",step+1,context!=NULL,status);
            if(status || !context)break;
            id helper=nil;
            @try {
                helper=[[helperClass alloc] initWithACMContext:context];
                BOOL satisfied=NO;
                if(!helper || !inspectEmptyOrMatchedContext(helper,parameters,"before-match",&satisfied) || satisfied) {
                    puts("ELAN_ACM_STOP initial context was not an empty unsatisfied context");break;
                }
                ElanpressFeatures *features=capture(&sensor);
                if(!features){puts("这次未采集到合格指纹。请结束后告知采集结果。");break;}
                unsigned score=match(features,prints,printCount);
                studyFreeFeatures(features);
                BOOL matched=score>=ELANPRESS_MATCH_MIN_PAIRS;
                printf("ELAN_ACM_MATCH step=%d expected=%s score=%u matched=%d\n",step+1,step==0?"other":"enrolled",score,matched);
                if(step==0 && matched) {
                    puts("未录入手指出现匹配，本轮停止，未提交系统凭据。");break;
                }
                if(matched && !cancelled) {
                    NSError *error=nil;
                    // 24H32 maps biometric requirement 3 to credential 3; the default context scope is 1.
                    BOOL added=[helper addCredential:3 scope:1 error:&error];
                    printf("ELAN_ACM_SUBMIT added=%d error_domain=%s error=%ld\n",added,error?error.domain.UTF8String:"none",(long)error.code);
                } else puts("ELAN_ACM_SUBMIT skipped=no-live-match");
                if(!inspectEmptyOrMatchedContext(helper,parameters,"after-match",&satisfied))break;
                printf("ELAN_ACM_RESULT step=%d live_match=%d native_satisfied=%d\n",step+1,matched,satisfied);
                if(step==1)result=0;
            } @finally {
                helper=nil;
                printf("ELAN_ACM_CONTEXT deleted_status=%d\n",deleteContext(context,true));
            }
        }
    } @finally {
        if(stored)wipe(stored.mutableBytes,stored.length);
        clearPrints();close_sensor(&sensor);
        puts("测试结束，临时认证上下文已释放。");
    }
    return result;
}

int main(int argc,char **argv) {
    @autoreleasepool {
        setbuf(stdout,NULL);
        if(argc==2 && !strcmp(argv[1],"--self-test"))return self_test()|template_self_test()|authPeerSelfTest()|captureStudySelfTest();
        if(argc==2 && !strcmp(argv[1],"--match-study"))return elanCredentialStudy();
        return 64;
    }
}
