#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Cocoa/Cocoa.h>
#import <SecurityInterface/SFAuthorizationPluginView.h>
#include <dlfcn.h>
#include "ElanAuthProtocol.h"
#include "ElanAuthSubmission.h"

static int results=0,contexts=0,invalidFlags=0,failPassword=0,removed=0;
static AuthorizationResult lastDecision;
static OSStatus result(AuthorizationEngineRef engine,AuthorizationResult decision){results++;lastDecision=decision;return noErr;}
static OSStatus deactivated(AuthorizationEngineRef engine){return noErr;}
static OSStatus context(AuthorizationEngineRef engine,AuthorizationString key,AuthorizationContextFlags flags,const AuthorizationValue *value) {
    contexts++;
    if(flags&kAuthorizationContextFlagExtractable || !(flags&kAuthorizationContextFlagVolatile))invalidFlags++;
    return failPassword&&!strcmp(key,kAuthorizationEnvironmentPassword)?errAuthorizationInternal:noErr;
}
static OSStatus removeContext(AuthorizationEngineRef engine,AuthorizationString key){removed++;return noErr;}
static OSStatus readContext(AuthorizationEngineRef engine,AuthorizationString key,AuthorizationContextFlags *flags,const AuthorizationValue **value){*value=NULL;return errAuthorizationInternal;}
static OSStatus readHint(AuthorizationEngineRef engine,AuthorizationString key,const AuthorizationValue **value){*value=NULL;return errAuthorizationInternal;}

static int probeTests(const char *bundle) {
    int ok=1,fd[2];uint32_t kind;size_t length;
    unsigned char body[ElanAuthMaxPayload]={0};void *password;size_t passwordLength;
    unsigned char fixture[]="fixture-user\0fixture:password";
    ok&=elan_auth_credentials(fixture,sizeof(fixture)-1,"fixture-user",&password,&passwordLength)&&passwordLength==16;
    ok&=!elan_auth_credentials(fixture,sizeof(fixture)-1,"another-user",&password,&passwordLength);
    ok&=!elan_auth_credentials(fixture,13,"fixture-user",&password,&passwordLength);
    ok&=!elan_auth_credentials(fixture,sizeof(fixture),"fixture-user",&password,&passwordLength);
    if(socketpair(AF_UNIX,SOCK_STREAM,0,fd))return 1;
    elan_auth_socket_options(fd[0]);elan_auth_socket_options(fd[1]);
    ok&=elan_auth_send(fd[0],ElanAuthMatch,fixture,sizeof(fixture)-1);
    ok&=elan_auth_receive(fd[1],&kind,body,&length)&&kind==ElanAuthMatch&&length==sizeof(fixture)-1&&!memcmp(body,fixture,length);
    uint32_t oversized[]={htonl(ElanAuthMatch),htonl(ElanAuthMaxPayload+1)};
    ok&=elan_auth_transfer(fd[0],oversized,sizeof(oversized),1)&&!elan_auth_receive(fd[1],&kind,body,&length);
    close(fd[0]);close(fd[1]);elan_auth_wipe(body,sizeof(body));
    printf("Auth framing / account binding / size limits: %s\n",ok?"pass":"fail");
    AuthorizationCallbacks callbacks={.version=kAuthorizationCallbacksVersion,.SetResult=result,.DidDeactivate=deactivated,.SetContextValue=context,.RemoveContextValue=removeContext,.GetContextValue=readContext,.GetHintValue=readHint};
    AuthorizationEngineRef engine=(AuthorizationEngineRef)1;
    int handoff=elan_auth_submit(&callbacks,engine,"fixture-user",fixture,4)==noErr&&contexts==2&&!invalidFlags&&!results;
    failPassword=1;
    handoff&=elan_auth_submit(&callbacks,engine,"fixture-user",fixture,4)!=noErr&&removed==2&&!results;
    printf("Auth credential handoff / private context / failure cleanup: %s\n",handoff?"pass":"fail");ok&=handoff;
    void *handle=dlopen(bundle,RTLD_NOW|RTLD_LOCAL);
    if(!handle){fprintf(stderr,"Plugin load failed: %s\n",dlerror());return 1;}
    OSStatus (*create)(const AuthorizationCallbacks*,AuthorizationPluginRef*,const AuthorizationPluginInterface**)=dlsym(handle,"AuthorizationPluginCreate");
    AuthorizationPluginRef plugin=NULL;const AuthorizationPluginInterface *interface=NULL;AuthorizationMechanismRef mechanism=NULL;
    int loaded=create&&create(&callbacks,&plugin,&interface)==noErr&&plugin&&interface;
    if(loaded) {
        loaded&=interface->MechanismCreate(plugin,engine,"unknown",&mechanism)!=noErr;
        loaded&=interface->MechanismCreate(plugin,engine,"fingerprint",&mechanism)==noErr;
        if(mechanism){loaded&=interface->MechanismDeactivate(mechanism)==noErr;loaded&=interface->MechanismDestroy(mechanism)==noErr;}
        loaded&=!results;
        int savedContexts=contexts;
        mechanism=NULL;
        loaded&=interface->MechanismCreate(plugin,engine,"credential-probe",&mechanism)==noErr;
        if(mechanism){
            loaded&=interface->MechanismInvoke(mechanism)==noErr;
            loaded&=results==1&&lastDecision==kAuthorizationResultDeny&&contexts==savedContexts;
            loaded&=interface->MechanismDeactivate(mechanism)==noErr;
            loaded&=interface->MechanismDestroy(mechanism)==noErr;
        }
        loaded&=interface->PluginDestroy(plugin)==noErr;
    }
    printf("Auth bundle loading / mechanism lifecycle / no implicit grant: %s\n",loaded?"pass":"fail");
    [NSApplication sharedApplication];
    NSString *bundlePath=[NSString stringWithUTF8String:bundle];
    for(int i=0;i<3;i++)bundlePath=bundlePath.stringByDeletingLastPathComponent;
    NSBundle *resources=[NSBundle bundleWithPath:bundlePath];
    NSNib *nib=[[NSNib alloc]initWithNibNamed:@"ElanAuthView" bundle:resources];
    NSArray *objects=nil;
    int decoded=nib&&[nib instantiateWithOwner:nil topLevelObjects:&objects];
    printf("Auth view resource decoding: %s\n",decoded?"pass":"fail");
    return ok&&loaded&&decoded?0:1;
}

static int requestTestRight(BOOL credentialProbe) {
    CFDictionaryRef rule=NULL;
    OSStatus status=AuthorizationRightGet(ELAN_AUTH_TEST_RIGHT,&rule);
    if(status!=errAuthorizationSuccess || !rule){fputs("The isolated ELAN test right is not installed.\n",stderr);return 1;}
    NSDictionary *definition=CFBridgingRelease(rule);
    NSArray *expected=credentialProbe?@[@"ELANFingerprintAuth:credential-probe,privileged"]:
        @[@"ELANFingerprintAuth:fingerprint",@"builtin:authenticate,privileged"];
    if(![definition[@"class"] isEqual:@"evaluate-mechanisms"] || ![definition[@"mechanisms"] isEqual:expected]) {
        fputs("The ELAN test rule differs from the expected authentication chain.\n",stderr);return 1;
    }
    AuthorizationRef authorization=NULL;
    status=AuthorizationCreate(NULL,NULL,kAuthorizationFlagDefaults,&authorization);
    if(status==noErr) {
        AuthorizationItem item={ELAN_AUTH_TEST_RIGHT,0,NULL,0};AuthorizationRights rights={1,&item};
        status=AuthorizationCopyRights(authorization,&rights,kAuthorizationEmptyEnvironment,
            kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights,NULL);
        AuthorizationFree(authorization,kAuthorizationFlagDestroyRights);
    }
    if(credentialProbe) {
        printf("Credential research authorization result: %d (%s)\n",(int)status,
               status==errAuthorizationDenied?"expected denial; no authorization granted":"unexpected result");
        return status==errAuthorizationDenied?0:1;
    }
    printf("System authorization result: %d (%s)\n",(int)status,status==noErr?"accepted":status==errAuthorizationCanceled?"cancelled":"not accepted");
    return status==noErr?0:status==errAuthorizationCanceled?2:1;
}

int main(int argc,char **argv){@autoreleasepool {setbuf(stdout,NULL);
    if(argc==2&&!strcmp(argv[1],"--request"))return requestTestRight(NO);
    if(argc==2&&!strcmp(argv[1],"--credential-request"))return requestTestRight(YES);
    if(argc==3&&!strcmp(argv[1],"--self-test"))return probeTests(argv[2]);
    fputs("Usage: elan-auth-probe --self-test BUNDLE_EXECUTABLE | --request | --credential-request\n",stderr);return 1;
}}
