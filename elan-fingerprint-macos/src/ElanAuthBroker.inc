#include "ElanAuthProtocol.h"
#include <mach/message.h>
#include <pwd.h>
#include <poll.h>
#include <sys/stat.h>

static int authClient=-1;

static BOOL authPeerIsSecurityAgent(int fd) {
    audit_token_t token;
    socklen_t length=sizeof(token);
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&length) || length!=sizeof(token)) return NO;
    SecCodeRef code=NULL;
    SecRequirementRef requirement=NULL;
    NSDictionary *attributes=@{(__bridge id)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
    OSStatus status=SecCodeCopyGuestWithAttributes(NULL,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code);
    if(status==errSecSuccess) status=SecRequirementCreateWithString(
        CFSTR("anchor apple and (identifier \"com.apple.SecurityAgent\" or identifier \"com.apple.SecurityAgentHelper.x86_64\" or identifier \"com.apple.SecurityAgentHelper.arm64\")"),
        kSecCSDefaultFlags,&requirement);
    if(status==errSecSuccess) status=SecCodeCheckValidity(code,kSecCSStrictValidate,requirement);
    if(requirement)CFRelease(requirement);
    if(code)CFRelease(code);
    return status==errSecSuccess;
}

static int authClientDisconnected(void) {
    unsigned char b;
    ssize_t n=recv(authClient,&b,1,MSG_PEEK|MSG_DONTWAIT);
    return n==0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR);
}

static void authProgress(const char *message) {
    if(authClient>=0) elan_auth_send(authClient,ElanAuthProgress,message,strlen(message));
}

static void authError(const char *message) {
    elan_auth_send(authClient,ElanAuthError,message,strlen(message));
}

static void authCaptureRequest(void) {
    unsigned char body[ElanAuthMaxPayload]={0};
    uint32_t kind=0;size_t length=0;
    NSMutableData *stored=NULL,*password=NULL;
    ElanpressFeatures *features=NULL;
    clearPrints();close_sensor(&sensor);
    if(!elan_auth_receive(authClient,&kind,body,&length) || kind!=ElanAuthRequest || length!=0) goto done;
    capture_status=authProgress;capture_should_cancel=authClientDisconnected;capture_timeout_seconds=25;
    if(!open_sensor(&sensor)){authError("指纹设备无法打开，请先停止其他指纹采集。");goto done;}
    stored=loadSecret(@"fingerprints-v1",NO);
    if(!unpackPrints(stored)){authError("无法读取已录入的指纹，请在 ELAN 应用中验证一次并允许钥匙串访问。");goto done;}
    wipe(stored.mutableBytes,stored.length);stored=nil;
    features=capture(&sensor);
    if(cancelled || authClientDisconnected()) goto done;
    if(!features){authError("没有取得清晰指纹，请松开后重试。");goto done;}
    unsigned score=match(features,prints,printCount);
    printf("AUTH score=%u matched=%d\n",score,score>=ELANPRESS_MATCH_MIN_PAIRS);
    if(score<ELANPRESS_MATCH_MIN_PAIRS){elan_auth_send(authClient,ElanAuthNoMatch,NULL,0);goto done;}
    if(authClientDisconnected())goto done;
    password=loadSecret(@"login-password",NO);
    if(!password.length || password.length>ElanAuthMaxPassword || memchr(password.bytes,0,password.length)) {
        authError("无法读取登录密码，请在 ELAN 应用中重新保存密码。");goto done;
    }
    struct passwd *user=getpwuid(geteuid());
    if(!user || strlen(user->pw_name)>255){authError("无法确认当前账户。");goto done;}
    size_t nameLength=strlen(user->pw_name)+1;
    memcpy(body,user->pw_name,nameLength);memcpy(body+nameLength,password.bytes,password.length);
    elan_auth_send(authClient,ElanAuthMatch,body,nameLength+password.length);
done:
    if(stored)wipe(stored.mutableBytes,stored.length);
    if(password)wipe(password.mutableBytes,password.length);
    elan_auth_wipe(body,sizeof(body));
    elanpress_features_free(features);clearPrints();close_sensor(&sensor);
    capture_status=NULL;capture_should_cancel=NULL;capture_timeout_seconds=90;
}

static int authBrokerMain(void) {
    if(geteuid()==0){fputs("Run the authentication broker as the logged-in user.\n",stderr);return 1;}
    char path[104];elan_auth_path(geteuid(),path);
    struct sockaddr_un address={.sun_family=AF_UNIX};strlcpy(address.sun_path,path,sizeof(address.sun_path));
    int server=socket(AF_UNIX,SOCK_STREAM,0);
    if(server<0)return 1;
    mode_t oldMask=umask(0077);
    int bound=bind(server,(struct sockaddr *)&address,sizeof(address));
    umask(oldMask);
    if(bound){perror("bind authentication broker");close(server);return 1;}
    struct stat owned={0};
    BOOL haveIdentity=lstat(path,&owned)==0;
    int result=1;
    /* SecurityAgent runs under a different UID; its Apple signature gates each accepted peer. */
    if(!haveIdentity || chmod(path,0666) || listen(server,2))goto done;
    signal(SIGTERM,interrupt);signal(SIGINT,interrupt);
    cancelled=0;result=0;
    printf("AUTH broker ready uid=%u\n",geteuid());
    while(!cancelled) {
        struct pollfd ready={server,POLLIN,0};
        int n=poll(&ready,1,250);
        if(n<0 && errno==EINTR)continue;
        if(n<0){result=1;break;}
        if(!n)continue;
        authClient=accept(server,NULL,NULL);
        if(authClient<0)continue;
        @autoreleasepool {
            if(elan_auth_socket_options(authClient) && authPeerIsSecurityAgent(authClient))authCaptureRequest();
            else puts("AUTH rejected untrusted peer");
        }
        close(authClient);authClient=-1;
    }
done:
    close(server);
    struct stat current;
    if(haveIdentity && lstat(path,&current)==0 && current.st_dev==owned.st_dev && current.st_ino==owned.st_ino)unlink(path);
    return result;
}

static int authBrokerPrepare(void) {
    /* Run in the desktop session so Keychain can request access after an
     * app update, before SecurityAgent begins a noninteractive request. */
    for(NSString *name in @[@"fingerprints-v1",@"login-password"]) {
        NSMutableData *data=loadSecret(name,YES);
        if(!data.length) {
            puts("AUTH setup failed: allow Keychain access in the desktop session, then retry.");
            return 1;
        }
        wipe(data.mutableBytes,data.length);
    }
    puts("AUTH Keychain access prepared");
    return authBrokerMain();
}

static int authPeerSelfTest(void) {
    int fd[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,fd))return 1;
    BOOL denied=!authPeerIsSecurityAgent(fd[0]);close(fd[0]);close(fd[1]);
    printf("Auth peer rejects ordinary process: %s\n",denied?"pass":"fail");
    return denied?0:1;
}
