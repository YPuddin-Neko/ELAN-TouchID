#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

@interface NSObject (ACMResearch)
- (instancetype)initWithACMContext:(void *)context;
+ (const char *)acmPolicyForPolicy:(NSInteger)policy;
- (void)preflightPolicy:(const char *)policy parameters:(const void *)parameters
       parametersCount:(unsigned)count maxGlobalCredentialAge:(unsigned)age
    processRequirement:(void (^)(int,bool,const void *,NSError *))completion;
@end

static unsigned spoofCalls;
static void *biometricFramework;

static void protocolMetadata(void) {
    unsigned count=0;Protocol *__unsafe_unretained *protocols=objc_copyProtocolList(&count);
    for(unsigned i=0;i<count;i++) {
        const char *name=protocol_getName(protocols[i]);
        if(!strstr(name,"BiometricKit") && strncmp(name,"BK",2))continue;
        printf("PROTOCOL %s\n",name);
        for(int required=0;required<2;required++) {
            unsigned methodCount=0;
            struct objc_method_description *methods=protocol_copyMethodDescriptionList(protocols[i],required,YES,&methodCount);
            for(unsigned j=0;j<methodCount;j++)
                printf("PROTOCOL_METHOD required=%d %s %s\n",required,sel_getName(methods[j].name),methods[j].types);
            free(methods);
        }
    }
    free(protocols);
}

static void credentialMetadata(void) {
    const char *path="/System/Library/Frameworks/LocalAuthentication.framework/Support/SharedUtils.framework/Versions/A/SharedUtils";
    if(!dlopen(path,RTLD_LAZY|RTLD_LOCAL)){printf("CREDENTIAL_LOAD_ERROR %s\n",dlerror());return;}
    Class cls=objc_getClass("LAACMHelper");
    printf("CREDENTIAL_CLASS %s\n",cls?class_getName(cls):"missing");
    for(int meta=0;meta<2;meta++) {
        unsigned count=0;Method *list=class_copyMethodList(meta?object_getClass(cls):cls,&count);
        for(unsigned i=0;i<count;i++)printf("CREDENTIAL_METHOD %c%s %s\n",meta?'+':'-',
                                           sel_getName(method_getName(list[i])),method_getTypeEncoding(list[i]));
        free(list);
    }
}

static void nativeUIMetadata(void) {
    const char *frameworks[]={"LocalAuthenticationUI","LocalAuthenticationCoreUI"};
    for(unsigned framework=0;framework<2;framework++) {
        NSString *path=[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/%s.framework/%s",frameworks[framework],frameworks[framework]];
        if(!dlopen(path.UTF8String,RTLD_LAZY|RTLD_LOCAL)) {
            printf("NATIVE_UI_LOAD %s %s\n",frameworks[framework],dlerror());continue;
        }
    }
    unsigned imageCount=0;const char **images=objc_copyImageNames(&imageCount);
    for(unsigned i=0;i<imageCount;i++) {
        if(!strstr(images[i],"/LocalAuthenticationUI.framework/") && !strstr(images[i],"/LocalAuthenticationCoreUI.framework/"))continue;
        unsigned count=0;const char **names=objc_copyClassNamesForImage(images[i],&count);
        for(unsigned j=0;j<count;j++) {
            Class cls=objc_getClass(names[j]);
            printf("NATIVE_UI_CLASS %s super=%s\n",names[j],class_getName(class_getSuperclass(cls)));
            for(int meta=0;meta<2;meta++) {
                unsigned methods=0;Method *list=class_copyMethodList(meta?object_getClass(cls):cls,&methods);
                for(unsigned k=0;k<methods;k++)printf("NATIVE_UI_METHOD %s %c%s %s\n",names[j],meta?'+':'-',sel_getName(method_getName(list[k])),method_getTypeEncoding(list[k]));
                free(list);
            }
        }
        free(names);
    }
    free(images);
}

static int publicContextExportProbe(void) {
    LAContext *context=[LAContext new];
    NSError *error=nil;
    BOOL available=[context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error];
    printf("OWN_CONTEXT password_policy_available=%d error=%ld\n",available,(long)error.code);
    SEL selector=sel_registerName("externalizedContext");
    Method method=class_getInstanceMethod([LAContext class],selector);
    printf("OWN_CONTEXT export_selector=%d encoding=%s\n",method!=NULL,method?method_getTypeEncoding(method):"missing");
    char *returnType=method?method_copyReturnType(method):NULL;
    if(method && method_getNumberOfArguments(method)==2 && returnType && returnType[0]=='@') {
        id value=((id(*)(id,SEL))objc_msgSend)(context,selector);
        printf("OWN_CONTEXT exported_data=%d length=%lu\n",[value isKindOfClass:[NSData class]],
               [value isKindOfClass:[NSData class]]?(unsigned long)[value length]:0);
        value=nil;
    }
    free(returnType);
    [context invalidate];
    puts("OWN_CONTEXT invalidated=1");
    return 0;
}

static int credentialContextProbe(BOOL inspectRequirements) {
    const char *root="/System/Library/Frameworks/LocalAuthentication.framework/Support/";
    NSString *directory=[NSString stringWithUTF8String:root];
    void *shared=dlopen([[directory stringByAppendingString:@"SharedUtils.framework/Versions/A/SharedUtils"] UTF8String],RTLD_LAZY|RTLD_LOCAL);
    void *daemon=dlopen([[directory stringByAppendingString:@"DaemonUtils.framework/Versions/A/DaemonUtils"] UTF8String],RTLD_LAZY|RTLD_LOCAL);
    int (*createContext)(void **)=daemon?dlsym(daemon,"ACMContextCreate"):NULL;
    int (*deleteContext)(void *,bool)=daemon?dlsym(daemon,"ACMContextDelete"):NULL;
    unsigned (*requirementType)(const void *)=daemon?dlsym(daemon,"ACMRequirementGetType"):NULL;
    unsigned (*requirementState)(const void *)=daemon?dlsym(daemon,"ACMRequirementGetState"):NULL;
    NSString *(*requirementDescription)(const void *)=shared?dlsym(shared,"NSStringFromACMRequirement"):NULL;
    Class helperClass=objc_getClass("LAACMHelper");
    if(!shared || !helperClass || !createContext || !deleteContext || !requirementType || !requirementState) {
        puts("ACM_SETUP missing helper or entrypoint");return 4;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),dispatch_get_global_queue(0,0),^{
        puts("ACM_TIMEOUT");fflush(stdout);_Exit(124);
    });
    void *context=NULL;
    int status=createContext(&context);
    printf("ACM_CONTEXT created=%d status=%d\n",context!=NULL,status);
    if(status || !context)return 5;
    @try {
        id helper=[[helperClass alloc] initWithACMContext:context];
        id userParameters=nil;
        if(inspectRequirements) {
            Class parameterClass=objc_getClass("LAManagedACMParameters");
            SEL userSelector=sel_registerName("acmParameterWithUserId:");
            if([parameterClass respondsToSelector:userSelector])
                userParameters=((id(*)(id,SEL,unsigned))objc_msgSend)(parameterClass,userSelector,getuid());
            printf("ACM_PARAMETERS uid=%u created=%d\n",getuid(),userParameters!=nil);
        }
        for(unsigned index=0;index<(inspectRequirements?4u:1u);index++) {
            NSInteger policyNumber=index%2?LAPolicyDeviceOwnerAuthentication:LAPolicyDeviceOwnerAuthenticationWithBiometrics;
            const char *policy=[helperClass acmPolicyForPolicy:policyNumber];
            id parameters=index>=2?userParameters:nil;
            const void *bytes=parameters?((const void *(*)(id,SEL))objc_msgSend)(parameters,sel_registerName("acmParameters")):NULL;
            unsigned count=parameters?((unsigned(*)(id,SEL))objc_msgSend)(parameters,sel_registerName("count")):0;
            printf("ACM_POLICY name=%s parameter_count=%u\n",policy?policy:"missing",count);
            if(!helper || !policy)continue;
            __block BOOL replied=NO;
            [helper preflightPolicy:policy parameters:bytes parametersCount:count maxGlobalCredentialAge:0
                processRequirement:^(int result,bool satisfied,const void *requirement,NSError *error) {
                    replied=YES;
                    printf("ACM_PREFLIGHT status=%d satisfied=%d requirement_type=%u requirement_state=%u error_domain=%s error=%ld\n",
                           result,satisfied,requirementType(requirement),requirementState(requirement),
                           error?error.domain.UTF8String:"none",(long)error.code);
                    if(inspectRequirements && requirement && requirementDescription)
                        printf("ACM_REQUIREMENT %s\n",requirementDescription(requirement).UTF8String);
                }];
            printf("ACM_PREFLIGHT callback_returned=%d\n",replied);
        }
        helper=nil;
    } @finally {
        printf("ACM_CONTEXT deleted_status=%d\n",deleteContext(context,true));
    }
    return 0;
}
static BOOL spoofDeviceAvailable(id object,SEL selector,char *failure) {
    spoofCalls++;if(failure)*failure=0;return YES;
}
static BOOL spoofTouchAvailable(id object,SEL selector,long *info) {
    spoofCalls++;if(info)*info=0;return YES;
}

typedef struct {
    volatile uint8_t *checked,*result;
    uint8_t oldChecked,oldResult;
} PlatformCache;

static BOOL writableByte(volatile uint8_t *byte) {
    mach_vm_address_t address=(mach_vm_address_t)byte;
    mach_vm_size_t size=0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object=MACH_PORT_NULL;
    kern_return_t status=mach_vm_region(mach_task_self(),&address,&size,VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&info,&count,&object);
    if(object!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),object);
    printf("PLATFORM_REGION status=%d protection=%d contains=%d\n",status,
           status==KERN_SUCCESS?info.protection:0,
           status==KERN_SUCCESS && (mach_vm_address_t)byte>=address && (mach_vm_address_t)byte<address+size);
    return status==KERN_SUCCESS && (mach_vm_address_t)byte>=address &&
           (mach_vm_address_t)byte<address+size && (info.protection&VM_PROT_WRITE);
}

static BOOL overridePlatformCache(PlatformCache *cache) {
#if defined(__x86_64__)
    char build[64]={0};size_t length=sizeof(build);
    if(sysctlbyname("kern.osversion",build,&length,NULL,0) || strcmp(build,"24H32")) {
        printf("PLATFORM_SETUP unsupported build=%s\n",build);return NO;
    }
    uint8_t *function=dlsym(biometricFramework,"isTouchIDPlatformWithFailure");
    if(!function || function[0x43]!=0x80 || function[0x44]!=0x3d || function[0x49]!=0 ||
       function[0x9d]!=0xc6 || function[0x9e]!=0x05 || function[0xa3]!=1 ||
       function[0x23f]!=0x8a || function[0x240]!=0x1d) {
        puts("PLATFORM_SETUP instruction layout differs");return NO;
    }
    int32_t checkedRead,checkedWrite,resultRead;
    memcpy(&checkedRead,function+0x45,4);memcpy(&checkedWrite,function+0x9f,4);
    memcpy(&resultRead,function+0x241,4);
    cache->checked=function+0x4a+checkedRead;
    cache->result=function+0x245+resultRead;
    printf("PLATFORM_LAYOUT checked_references_agree=%d result_delta=%ld\n",
           cache->checked==function+0xa4+checkedWrite,(long)(cache->result-cache->checked));
    if(cache->checked!=function+0xa4+checkedWrite || cache->result!=cache->checked+1) {
        puts("PLATFORM_SETUP cache layout differs");return NO;
    }
    BOOL (*platform)(char *)=(BOOL(*)(char *))function;
    char failure=0;
    BOOL available=platform(&failure);
    cache->oldChecked=*cache->checked;cache->oldResult=*cache->result;
    printf("PLATFORM phase=baseline available=%d failure=%d checked=%u result=%u\n",
           available,failure,cache->oldChecked,cache->oldResult);
    if(!writableByte(cache->checked) || !writableByte(cache->result)) {
        puts("PLATFORM_SETUP cache is not writable");return NO;
    }
    *cache->result=1;*cache->checked=1;
    printf("PLATFORM phase=process-local-spoof available=%d\n",platform(&failure));
    return YES;
#else
    puts("PLATFORM_SETUP unsupported architecture");return NO;
#endif
}

static IMP originalConnectionResume;
static void observedConnectionResume(id object,SEL selector) {
    NSString *name=[(NSXPCConnection *)object serviceName];
    printf("XPC_SERVICE name=%s\n",name?name.UTF8String:"none");
    if([name isEqualToString:@"com.apple.biometrickitd"]) {
        puts("XPC_SERVICE transport deferred for factory-only probe");return;
    }
    ((void(*)(id,SEL))originalConnectionResume)(object,selector);
}

#include "native-xpc-transport.inc"
#include "native-xpc-process.inc"

static void deviceBackendSnapshot(BOOL readHardwareState) {
    Class manager=objc_getClass("BKDeviceManager");
    id devices=((id(*)(id,SEL))objc_msgSend)(manager,sel_registerName("availableDevices"));
    if(![devices respondsToSelector:@selector(count)] || ![devices count]){puts("DEVICE_BACKEND no descriptor");return;}
    id descriptor=[devices objectAtIndex:0];
    NSError *error=nil;
    id device=((id(*)(id,SEL,id,NSError**))objc_msgSend)(objc_getClass("BKDevice"),sel_registerName("deviceWithDescriptor:error:"),descriptor,&error);
    printf("DEVICE_BACKEND descriptor=%s device=%s error_domain=%s error=%ld\n",
           object_getClassName(descriptor),device?object_getClassName(device):"nil",error?error.domain.UTF8String:"none",(long)error.code);
    if(device && readHardwareState && [device respondsToSelector:sel_registerName("deviceHardwareState:error:")]) {
        unsigned long long state=0;error=nil;
        BOOL ok=((BOOL(*)(id,SEL,unsigned long long*,NSError**))objc_msgSend)(device,sel_registerName("deviceHardwareState:error:"),&state,&error);
        printf("DEVICE_HARDWARE readable=%d state=%llu error_domain=%s error=%ld\n",ok,state,error?error.domain.UTF8String:"none",(long)error.code);
    }
}

static void capabilitySnapshot(const char *label) {
    Class manager=objc_getClass("BKDeviceManager");
    SEL devicesSelector=sel_registerName("availableDevices");
    if([manager respondsToSelector:devicesSelector]) {
        id devices=((id(*)(id,SEL))objc_msgSend)(manager,devicesSelector);
        printf("PRIVATE_DEVICES phase=%s class=%s count=%lu\n",label,
               devices?object_getClassName(devices):"nil",
               [devices respondsToSelector:@selector(count)]?(unsigned long)[devices count]:0);
    }
    Class touch=objc_getClass("BKDeviceTouchID");
    SEL available=sel_registerName("deviceAvailableWithFailure:");
    if([touch respondsToSelector:available]) {
        char failure=0;
        BOOL value=((BOOL(*)(id,SEL,char*))objc_msgSend)(touch,available,&failure);
        printf("PRIVATE_TOUCH phase=%s available=%d failure=%d spoof_calls=%u\n",label,value,failure,spoofCalls);
    }
    LAContext *context=[LAContext new];NSError *error=nil;
    BOOL value=[context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    printf("PUBLIC_LA phase=%s available=%d type=%ld error=%ld spoof_calls=%u\n",label,value,(long)context.biometryType,(long)error.code,spoofCalls);
}

/* The optional replacements affect this process's capability checks only. */
#ifndef NATIVE_STACK_NO_MAIN
int main(int argc,char **argv) {
    @autoreleasepool {
        setbuf(stdout,NULL);
        const char *path="/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit";
        biometricFramework=dlopen(path,RTLD_LAZY|RTLD_LOCAL);
        if(!biometricFramework){printf("LOAD_ERROR %s\n",dlerror());return 1;}
        if(argc==2 && !strcmp(argv[1],"--protocols")){protocolMetadata();return 0;}
        if(argc==2 && !strcmp(argv[1],"--credential-metadata")){credentialMetadata();return 0;}
        if(argc==2 && !strcmp(argv[1],"--native-ui-metadata")){nativeUIMetadata();return 0;}
        if(argc==2 && !strcmp(argv[1],"--public-context-export"))return publicContextExportProbe();
        if(argc==2 && !strcmp(argv[1],"--xpc-transport"))return nativeXPCTransportProbe(NO);
        if(argc==2 && !strcmp(argv[1],"--xpc-match-control"))return nativeXPCTransportProbe(YES);
        if(argc==2 && !strcmp(argv[1],"--xpc-context-options"))return nativeXPCTransportProbe(2);
        if(argc==2 && !strcmp(argv[1],"--xpc-process"))return nativeXPCProcessProbe();
        if(argc==2 && (!strcmp(argv[1],"--credential-context") || !strcmp(argv[1],"--credential-requirements")))
            return credentialContextProbe(!strcmp(argv[1],"--credential-requirements"));
        if(argc==2 && (!strcmp(argv[1],"--capability") || !strcmp(argv[1],"--spoof-capability") || !strcmp(argv[1],"--spoof-device") || !strcmp(argv[1],"--spoof-platform"))) {
            if(strcmp(argv[1],"--capability")) {
                BOOL platformMode=!strcmp(argv[1],"--spoof-platform");
                PlatformCache cache={0};
                if(platformMode && !overridePlatformCache(&cache))return 3;
                Method machService=NULL;
                if(platformMode) {
                    machService=class_getInstanceMethod([NSXPCConnection class],@selector(resume));
                    originalConnectionResume=method_setImplementation(machService,(IMP)observedConnectionResume);
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC),dispatch_get_global_queue(0,0),^{
                        puts("PROBE_TIMEOUT process exiting; private memory changes discarded");fflush(stdout);_Exit(124);
                    });
                }
                Method touch=class_getClassMethod(objc_getClass("BKDeviceTouchID"),sel_registerName("deviceAvailableWithFailure:"));
                Method biometric=class_getInstanceMethod(objc_getClass("BiometricKit"),sel_registerName("isTouchIDAvailableWithInfo:"));
                if(!touch || !biometric){puts("SPOOF_SETUP missing method");return 2;}
                IMP oldTouch=method_setImplementation(touch,(IMP)spoofDeviceAvailable);
                IMP oldBiometric=method_setImplementation(biometric,(IMP)spoofTouchAvailable);
                @try {
                    capabilitySnapshot("process-local-spoof");
                    if(!strcmp(argv[1],"--spoof-device") || platformMode)deviceBackendSnapshot(!platformMode);
                } @finally {
                    method_setImplementation(touch,oldTouch);method_setImplementation(biometric,oldBiometric);
                    if(platformMode) {
                        method_setImplementation(machService,originalConnectionResume);
                        *cache.result=cache.oldResult;*cache.checked=cache.oldChecked;
                        BOOL (*platform)(char *)=dlsym(biometricFramework,"isTouchIDPlatformWithFailure");
                        printf("PLATFORM phase=restored available=%d\n",platform(NULL));
                    }
                }
                capabilitySnapshot("restored");
            } else capabilitySnapshot("baseline");
            return 0;
        }
        unsigned count=0;
        const char **images=objc_copyImageNames(&count);
        for(unsigned i=0;i<count;i++) {
            if(!strstr(images[i],"/BiometricKit.framework/"))continue;
            printf("IMAGE %s\n",images[i]);
            unsigned classes=0;const char **names=objc_copyClassNamesForImage(images[i],&classes);
            for(unsigned j=0;j<classes;j++) {
                Class cls=objc_getClass(names[j]);
                printf("CLASS %s\n",names[j]);
                for(int meta=0;meta<2;meta++) {
                    unsigned methods=0;Method *list=class_copyMethodList(meta?object_getClass(cls):cls,&methods);
                    for(unsigned k=0;k<methods;k++) {
                        NSString *name=NSStringFromSelector(method_getName(list[k]));
                        NSString *lower=name.lowercaseString;
                        BOOL selected=NO;
                        for(NSString *term in @[@"device",@"sensor",@"register",@"match",@"server",@"proxy",@"connect",@"available",@"capabil",@"enroll"])
                            if([lower containsString:term]){selected=YES;break;}
                        if(selected)printf("METHOD %s %c%s %s\n",names[j],meta?'+':'-',name.UTF8String,method_getTypeEncoding(list[k]));
                    }
                    free(list);
                }
            }
            free(names);
        }
        free(images);
    }
    return 0;
}
#endif
