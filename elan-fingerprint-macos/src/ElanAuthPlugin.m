#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <SecurityInterface/SFAuthorizationPluginView.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <pwd.h>
#include <syslog.h>
#include "ElanAuthProtocol.h"
#include "ElanAuthSubmission.h"
#include "ElanNativeCredentialProbe.inc"

@interface ElanAuthContent : NSObject {
    NSView *_content;
    NSTextField *_status;
    NSSecureTextField *_password;
    NSButton *_fingerButton, *_passwordButton;
    NSString *_username;
    uid_t _uid;
    NSLock *_socketLock;
    int _connection;
    NSUInteger _generation, _failures;
    BOOL _active, _finished, _running, _manual;
}
@property(nonatomic,readonly) const AuthorizationCallbacks *callbacks;
@property(nonatomic,readonly) AuthorizationEngineRef engineRef;
-(id)initWithCallbacks:(const AuthorizationCallbacks *)callbacks andEngineRef:(AuthorizationEngineRef)engine;
-(NSView *)viewForType:(SFViewType)type;
-(NSView *)firstKeyView;
-(NSResponder *)firstResponder;
-(NSView *)lastKeyView;
-(void)setEnabled:(BOOL)enabled;
-(void)willActivateWithUser:(NSDictionary *)information;
-(void)didActivate;
-(void)didDeactivate;
-(void)buttonPressed:(SFButtonType)button;
-(void)startCapture:(id)sender;
-(void)usePassword:(id)sender;
-(void)stop;
@end

@implementation ElanAuthContent
-(id)initWithCallbacks:(const AuthorizationCallbacks *)callbacks andEngineRef:(AuthorizationEngineRef)engine {
    self=[super init];
    if(!self)return nil;
    _callbacks=callbacks;_engineRef=engine;
    _connection=-1;_socketLock=[NSLock new];
    gid_t group=0;CFStringRef consoleUser=SCDynamicStoreCopyConsoleUser(NULL,&_uid,&group);
    if(consoleUser)CFRelease(consoleUser);
    struct passwd *user=_uid>=500?getpwuid(_uid):NULL;
    if(user)_username=[NSString stringWithUTF8String:user->pw_name];
    _content=[[NSView alloc]initWithFrame:NSMakeRect(0,0,394,220)];
    _content.autoresizingMask=NSViewWidthSizable;
    NSImageView *icon=[[NSImageView alloc]initWithFrame:NSMakeRect(0,164,44,44)];
    icon.image=[NSImage imageWithSystemSymbolName:@"touchid" accessibilityDescription:@"指纹"];
    icon.imageScaling=NSImageScaleProportionallyUpOrDown;[_content addSubview:icon];
    NSTextField *title=[NSTextField labelWithString:@"使用指纹验证"];
    title.font=[NSFont boldSystemFontOfSize:15];title.frame=NSMakeRect(58,187,336,22);
    title.autoresizingMask=NSViewWidthSizable;[_content addSubview:title];
    NSTextField *account=[NSTextField labelWithString:_username?[NSString stringWithFormat:@"账户：%@",_username]:@"请先登录账户"];
    account.frame=NSMakeRect(58,164,336,20);account.textColor=NSColor.secondaryLabelColor;
    account.autoresizingMask=NSViewWidthSizable;[_content addSubview:account];
    _status=[NSTextField wrappingLabelWithString:@"请松开手指，等待采集提示。"];
    _status.frame=NSMakeRect(0,90,394,58);_status.autoresizingMask=NSViewWidthSizable;[_content addSubview:_status];
    _fingerButton=[NSButton buttonWithTitle:@"使用指纹" target:self action:@selector(startCapture:)];
    _fingerButton.frame=NSMakeRect(0,48,110,32);[_content addSubview:_fingerButton];
    _passwordButton=[NSButton buttonWithTitle:@"使用密码" target:self action:@selector(usePassword:)];
    _passwordButton.frame=NSMakeRect(122,48,110,32);[_content addSubview:_passwordButton];
    _password=[[NSSecureTextField alloc]initWithFrame:NSMakeRect(0,8,394,26)];
    _password.placeholderString=@"macOS 登录密码";_password.hidden=YES;
    _password.autoresizingMask=NSViewWidthSizable;[_content addSubview:_password];
    return self;
}
-(NSView *)viewForType:(SFViewType)type{return _content;}
-(NSView *)firstKeyView{return _manual?_password:_fingerButton;}
-(NSResponder *)firstResponder{return [self firstKeyView];}
-(NSView *)lastKeyView{return _manual?_password:_passwordButton;}
-(void)setEnabled:(BOOL)enabled {
    _fingerButton.enabled=enabled&&!_running&&_failures<4&&_username.length;
    _passwordButton.enabled=enabled&&_username.length;_password.enabled=enabled;
}
-(void)willActivateWithUser:(NSDictionary *)information {
    _active=YES;_finished=NO;
    NSString *selected=information[SFAuthorizationPluginViewUserShortNameKey];
    if(selected.length && ![selected isEqualToString:_username]) {
        _username=nil;_status.stringValue=@"此指纹属于当前登录账户，请选择该账户后重试。";
    }
    [self setEnabled:YES];
}
-(void)didActivate {
    if(_username.length && !_manual && !_running)[self startCapture:nil];
}
-(void)disconnect {
    [_socketLock lock];
    if(_connection>=0)shutdown(_connection,SHUT_RDWR);
    [_socketLock unlock];
}
-(void)stop {
    _active=NO;_generation++;[self disconnect];_password.stringValue=@"";
}
-(void)didDeactivate{[self stop];}
-(void)usePassword:(id)sender {
    _generation++;[self disconnect];_running=NO;_manual=YES;
    _password.hidden=NO;_status.stringValue=@"输入此账户的登录密码，然后点继续。";
    [self setEnabled:YES];[_content.window makeFirstResponder:_password];
}
-(void)submitPassword:(void *)bytes length:(size_t)length {
    if(!_active || _finished || !_username.length)return;
    OSStatus status=elan_auth_submit(self.callbacks,self.engineRef,_username.UTF8String,bytes,length);
    if(status!=errAuthorizationSuccess){_status.stringValue=@"无法提交验证信息，请重试或取消。";return;}
    _finished=YES;_generation++;[self disconnect];[self setEnabled:NO];
    if(self.callbacks->SetResult(self.engineRef,kAuthorizationResultAllow)!=noErr) {
        _finished=NO;_running=NO;_status.stringValue=@"系统未接受验证信息，请重试或取消。";[self setEnabled:YES];
    } else syslog(LOG_NOTICE,"ElanAuth: credentials handed to system authentication");
}
-(void)buttonPressed:(SFButtonType)button {
    if(!_active || _finished)return;
    if(button==SFButtonTypeCancel){
        syslog(LOG_NOTICE,"ElanAuth: user cancelled");
        _finished=YES;[self stop];self.callbacks->SetResult(self.engineRef,kAuthorizationResultUserCanceled);return;
    }
    if(button!=SFButtonTypeOK)return;
    if(!_manual){if(!_running)[self startCapture:nil];return;}
    NSMutableData *bytes=[[_password.stringValue dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    _password.stringValue=@"";
    if(!bytes.length){_status.stringValue=@"请输入登录密码。";return;}
    [self submitPassword:bytes.mutableBytes length:bytes.length];
    elan_auth_wipe(bytes.mutableBytes,bytes.length);
}
-(void)startCapture:(id)sender {
    if(!_active || _finished || _running || !_username.length || _failures>=4)return;
    _manual=NO;_password.hidden=YES;_password.stringValue=@"";_running=YES;
    _status.stringValue=@"正在连接指纹服务…";[self setEnabled:YES];
    NSUInteger generation=++_generation;NSString *username=_username;uid_t uid=_uid;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool {
        int fd=socket(AF_UNIX,SOCK_STREAM,0);
        NSString *error=@"指纹服务未运行，请启动 ELAN 指纹服务，或改用密码。";
        unsigned char body[ElanAuthMaxPayload]={0};
        BOOL completed=NO,matched=NO;
        NSMutableData *secret=nil;
        if(fd>=0 && elan_auth_socket_options(fd)) {
            struct sockaddr_un address={.sun_family=AF_UNIX};elan_auth_path(uid,address.sun_path);
            if(connect(fd,(struct sockaddr *)&address,sizeof(address))==0) {
                uid_t peer;gid_t group;
                if(getpeereid(fd,&peer,&group)==0 && peer==uid) {
                    __block BOOL current=NO;
                    dispatch_sync(dispatch_get_main_queue(),^{
                        current=self->_active&&self->_generation==generation;
                        if(current){[self->_socketLock lock];self->_connection=fd;[self->_socketLock unlock];}
                    });
                    if(current && elan_auth_send(fd,ElanAuthRequest,NULL,0)) {
                        uint32_t kind;size_t length;
                        error=@"连接已结束，请重试或改用密码。";
                        while(elan_auth_receive(fd,&kind,body,&length)) {
                            if(kind==ElanAuthProgress) {
                                NSString *message=[[NSString alloc]initWithBytes:body length:length encoding:NSUTF8StringEncoding];
                                if(message)dispatch_async(dispatch_get_main_queue(),^{if(self->_active&&self->_generation==generation)self->_status.stringValue=message;});
                            } else if(kind==ElanAuthMatch) {
                                void *password;size_t passwordLength;
                                if(elan_auth_credentials(body,length,username.UTF8String,&password,&passwordLength)) {
                                    secret=[NSMutableData dataWithBytes:password length:passwordLength];matched=YES;
                                } else error=@"指纹服务返回的账户信息不正确，请改用密码。";
                                completed=YES;break;
                            } else if(kind==ElanAuthNoMatch) {
                                error=@"指纹不匹配，请松开后重试。";completed=YES;break;
                            } else if(kind==ElanAuthError) {
                                error=[[NSString alloc]initWithBytes:body length:length encoding:NSUTF8StringEncoding]?:@"指纹服务发生错误，请改用密码。";
                                completed=YES;break;
                            } else {error=@"指纹服务返回的信息无效，请改用密码。";break;}
                            elan_auth_wipe(body,sizeof(body));
                        }
                    }
                } else error=@"无法确认指纹服务所属账户，请改用密码。";
            }
        }
        elan_auth_wipe(body,sizeof(body));
        [self->_socketLock lock];if(self->_connection==fd)self->_connection=-1;[self->_socketLock unlock];
        if(fd>=0)close(fd);
        dispatch_async(dispatch_get_main_queue(),^{
            if(self->_active && self->_generation==generation) {
                self->_running=NO;
                if(matched)[self submitPassword:secret.mutableBytes length:secret.length];
                else {
                    if(completed)self->_failures++;
                    self->_status.stringValue=self->_failures>=4?@"已尝试4次，请改用密码。":error;
                    [self setEnabled:YES];
                }
            }
            if(secret)elan_auth_wipe(secret.mutableBytes,secret.length);
        });
    }});
}
@end

@interface ElanAuthView:SFAuthorizationPluginView
@property ElanAuthContent *content;
-(void)stop;
@end
@implementation ElanAuthView
-(id)initWithCallbacks:(const AuthorizationCallbacks *)callbacks andEngineRef:(AuthorizationEngineRef)engine {
    self=[super initWithCallbacks:callbacks andEngineRef:engine];
    if(self)self.content=[[ElanAuthContent alloc]initWithCallbacks:callbacks andEngineRef:engine];
    return self;
}
-(NSView *)viewForType:(SFViewType)type{return [self.content viewForType:type];}
-(NSView *)firstKeyView{return self.content.firstKeyView;}
-(NSResponder *)firstResponder{return self.content.firstResponder;}
-(NSView *)lastKeyView{return self.content.lastKeyView;}
-(void)setEnabled:(BOOL)enabled{[self.content setEnabled:enabled];}
-(void)willActivateWithUser:(NSDictionary *)information{[self.content willActivateWithUser:information];}
-(void)didActivate{[self.content didActivate];}
-(void)didDeactivate{[self.content didDeactivate];}
-(void)buttonPressed:(SFButtonType)button{[self.content buttonPressed:button];}
-(void)stop{[self.content stop];}
@end

@interface ElanAuthPluginContext:NSObject
@property const AuthorizationCallbacks *callbacks;
@end
@implementation ElanAuthPluginContext @end
@interface ElanAuthMechanism:NSObject
@property ElanAuthPluginContext *plugin;
@property AuthorizationEngineRef engine;
@property ElanAuthView *view;
@property BOOL credentialProbe;
@end
@implementation ElanAuthMechanism @end

static void onAuthMain(dispatch_block_t block){if(NSThread.isMainThread)block();else dispatch_sync(dispatch_get_main_queue(),block);}
static OSStatus authPluginDestroy(AuthorizationPluginRef ref){CFBridgingRelease(ref);return noErr;}
static OSStatus authMechanismCreate(AuthorizationPluginRef plugin,AuthorizationEngineRef engine,AuthorizationMechanismId name,AuthorizationMechanismRef *out) {
    if((strcmp(name,"fingerprint") && strcmp(name,"credential-probe")) || !engine)return errAuthorizationInternal;
    ElanAuthMechanism *m=[ElanAuthMechanism new];m.plugin=(__bridge ElanAuthPluginContext *)plugin;m.engine=engine;
    m.credentialProbe=!strcmp(name,"credential-probe");
    *out=(__bridge_retained void *)m;return noErr;
}
static OSStatus authMechanismInvoke(AuthorizationMechanismRef ref) {
    ElanAuthMechanism *m=(__bridge ElanAuthMechanism *)ref;
    if(m.credentialProbe) {
        @try {elan_native_credential_probe();}
        @catch(NSException *exception){syslog(LOG_ERR,"ElanNativeProbe: exception=%s",exception.name.UTF8String);}
        @finally {m.plugin.callbacks->SetResult(m.engine,kAuthorizationResultDeny);}
        return noErr;
    }
    syslog(LOG_NOTICE,"ElanAuth: mechanism invoked uid=%u",geteuid());
    if(geteuid()==0){m.plugin.callbacks->SetResult(m.engine,kAuthorizationResultDeny);return noErr;}
    onAuthMain(^{@try {
        m.view=[[ElanAuthView alloc]initWithCallbacks:m.plugin.callbacks andEngineRef:m.engine];
        if(m.view){[m.view displayView];syslog(LOG_NOTICE,"ElanAuth: view displayed");}
        else {syslog(LOG_ERR,"ElanAuth: view initialization failed");m.plugin.callbacks->SetResult(m.engine,kAuthorizationResultDeny);}
    }@catch(NSException *exception){syslog(LOG_ERR,"ElanAuth: display exception %s",exception.name.UTF8String);m.plugin.callbacks->SetResult(m.engine,kAuthorizationResultDeny);}});
    return noErr;
}
static OSStatus authMechanismDeactivate(AuthorizationMechanismRef ref) {
    ElanAuthMechanism *m=(__bridge ElanAuthMechanism *)ref;
    if(m.credentialProbe)return m.plugin.callbacks->DidDeactivate(m.engine);
    onAuthMain(^{[m.view stop];});return m.plugin.callbacks->DidDeactivate(m.engine);
}
static OSStatus authMechanismDestroy(AuthorizationMechanismRef ref) {
    ElanAuthMechanism *m=CFBridgingRelease(ref);
    if(!m.credentialProbe)onAuthMain(^{[m.view stop];m.view=nil;});return noErr;
}
OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,AuthorizationPluginRef *outPlugin,const AuthorizationPluginInterface **outInterface) {
    if(!callbacks || !callbacks->SetResult || !callbacks->SetContextValue || !callbacks->DidDeactivate || !outPlugin || !outInterface)
        return errAuthorizationInvalidPointer;
    static const AuthorizationPluginInterface interface={kAuthorizationPluginInterfaceVersion,authPluginDestroy,authMechanismCreate,authMechanismInvoke,authMechanismDeactivate,authMechanismDestroy};
    ElanAuthPluginContext *plugin=[ElanAuthPluginContext new];plugin.callbacks=callbacks;
    *outPlugin=(__bridge_retained void *)plugin;*outInterface=&interface;return noErr;
}
