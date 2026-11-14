#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <ApplicationServices/ApplicationServices.h>
#import <OpenDirectory/OpenDirectory.h>
#import <LocalAuthentication/LocalAuthentication.h>
#define main elan_diagnostic_main
#include "elan_match_test.c"
#undef main

#include "ElanFingerprintStore.inc"
static BOOL screenLocked(void){CFDictionaryRef d=CGSessionCopyCurrentDictionary();if(!d)return NO;CFTypeRef v=CFDictionaryGetValue(d,CFSTR("CGSSessionScreenIsLocked"));BOOL yes=v&&CFGetTypeID(v)==CFBooleanGetTypeID()&&CFBooleanGetValue(v);CFRelease(d);return yes;}
static BOOL secureFocus(void){
 if(!screenLocked())return NO;
 AXUIElementRef sys=AXUIElementCreateSystemWide();CFTypeRef field=NULL;AXError e=AXUIElementCopyAttributeValue(sys,kAXFocusedUIElementAttribute,&field);CFRelease(sys);
 if(e!=kAXErrorSuccess||!field)return NO;pid_t pid=0;AXUIElementGetPid((AXUIElementRef)field,&pid);
 NSString *bid=[NSRunningApplication runningApplicationWithProcessIdentifier:pid].bundleIdentifier;
 CFTypeRef role=NULL,sub=NULL,val=NULL;
 AXUIElementCopyAttributeValue((AXUIElementRef)field,kAXRoleAttribute,&role);AXUIElementCopyAttributeValue((AXUIElementRef)field,kAXSubroleAttribute,&sub);
 BOOL secure=(role&&CFGetTypeID(role)==CFStringGetTypeID()&&CFEqual(role,CFSTR("AXSecureTextField")))||(sub&&CFGetTypeID(sub)==CFStringGetTypeID()&&CFEqual(sub,CFSTR("AXSecureTextField")));
 AXError ve=AXUIElementCopyAttributeValue((AXUIElementRef)field,kAXValueAttribute,&val);
 BOOL empty=ve==kAXErrorSuccess&&val&&CFGetTypeID(val)==CFStringGetTypeID()&&CFStringGetLength(val)==0;
 if(role)CFRelease(role);if(sub)CFRelease(sub);if(val)CFRelease(val);CFRelease(field);
 return secure&&empty&&[bid isEqualToString:@"com.apple.loginwindow"]&&screenLocked();
}
static NSString *enrollmentGuide(int count) {
    if(count<4)return @"同一手指，保持指腹中心";
    if(count<8)return @"指腹中心，小幅改变角度";
    NSArray *directions=@[@"左",@"右",@"前",@"后"];
    NSString *direction=directions[(count-8)/4];
    return (count-8)%4==0?[NSString stringWithFormat:@"回到中心，再向%@轻移",direction]:[NSString stringWithFormat:@"沿上次位置，向%@再轻移一点",direction];
}
static BOOL typePassword(NSString*p){if(p.length<1||p.length>256||!AXIsProcessTrusted()||!secureFocus())return NO;UniChar text[256]={0};[p getCharacters:text range:NSMakeRange(0,p.length)];CGEventRef down=CGEventCreateKeyboardEvent(NULL,0,true),up=CGEventCreateKeyboardEvent(NULL,0,false);if(!down||!up){if(down)CFRelease(down);if(up)CFRelease(up);wipe(text,sizeof(text));return NO;}CGEventKeyboardSetUnicodeString(down,p.length,text);CGEventKeyboardSetUnicodeString(up,p.length,text);CGEventSetFlags(down,0);CGEventSetFlags(up,0);if(!secureFocus()){CFRelease(down);CFRelease(up);wipe(text,sizeof(text));return NO;}CGEventPost(kCGSessionEventTap,down);CGEventPost(kCGSessionEventTap,up);CFRelease(down);CFRelease(up);wipe(text,sizeof(text));usleep(150000);if(!screenLocked())return YES;
 // Submit only while the focused application is still the lock screen.
 AXUIElementRef sys=AXUIElementCreateSystemWide();CFTypeRef f=NULL;pid_t pid=0;AXError er=AXUIElementCopyAttributeValue(sys,kAXFocusedUIElementAttribute,&f);CFRelease(sys);if(er!=kAXErrorSuccess||!f)return NO;AXUIElementGetPid((AXUIElementRef)f,&pid);CFRelease(f);if(![[NSRunningApplication runningApplicationWithProcessIdentifier:pid].bundleIdentifier isEqual:@"com.apple.loginwindow"])return NO;
 CGEventRef enter=CGEventCreateKeyboardEvent(NULL,0x24,true),release=CGEventCreateKeyboardEvent(NULL,0x24,false);if(!enter||!release){if(enter)CFRelease(enter);if(release)CFRelease(release);return NO;}CGEventSetFlags(enter,0);CGEventSetFlags(release,0);CGEventPost(kCGSessionEventTap,enter);CGEventPost(kCGSessionEventTap,release);CFRelease(enter);CFRelease(release);return YES;}
@interface Delegate:NSObject<NSApplicationDelegate,NSWindowDelegate>
@property NSWindow*window;@property NSTextField*status;@property NSSecureTextField*password;@property NSStatusItem*item;@property NSMenuItem*stateItem;@property(atomic) BOOL busy;@property(atomic) BOOL armed;@property NSString*phase;
-(void)message:(NSString*)s;
@end
static Delegate*delegate;
static void report(const char*s){printf("%s\n",s);fflush(stdout);NSString*text=[NSString stringWithUTF8String:s];dispatch_async(dispatch_get_main_queue(),^{[delegate message:text];});}
@implementation Delegate
-(void)message:(NSString*)s{self.status.stringValue=self.phase.length?[NSString stringWithFormat:@"%@\n%@",self.phase,s]:s;self.item.button.toolTip=self.status.stringValue;}
-(NSButton*)button:(NSString*)title y:(CGFloat)y action:(SEL)a{NSButton*b=[NSButton buttonWithTitle:title target:self action:a];b.frame=NSMakeRect(24,y,190,32);[self.window.contentView addSubview:b];return b;}
-(void)applicationDidFinishLaunching:(NSNotification*)n{delegate=self;capture_status=report;self.window=[[NSWindow alloc]initWithContentRect:NSMakeRect(0,0,520,370) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable backing:NSBackingStoreBuffered defer:NO];self.window.title=@"ELAN 指纹解锁";self.window.delegate=self;self.window.releasedWhenClosed=NO;[self.window center];
 self.status=[NSTextField wrappingLabelWithString:@"先录入并验证指纹，再保存本机密码，最后启用锁屏解锁。"];self.status.frame=NSMakeRect(24,268,470,76);[self.window.contentView addSubview:self.status];
 [self button:@"1. 录入 / 补充指纹" y:220 action:@selector(enroll:)];NSButton*verify=[NSButton buttonWithTitle:@"验证指纹" target:self action:@selector(verify:)];verify.frame=NSMakeRect(244,220,190,32);[self.window.contentView addSubview:verify];self.password=[NSSecureTextField new];self.password.frame=NSMakeRect(24,174,270,26);self.password.placeholderString=@"在这里输入 macOS 登录密码";[self.window.contentView addSubview:self.password];NSButton*save=[NSButton buttonWithTitle:@"2. 保存密码" target:self action:@selector(save:)];save.frame=NSMakeRect(308,170,150,32);[self.window.contentView addSubview:save];
 [self button:@"3. 启用锁屏解锁" y:118 action:@selector(arm:)];NSButton*stop=[NSButton buttonWithTitle:@"停止" target:self action:@selector(stop:)];stop.frame=NSMakeRect(244,118,100,32);[self.window.contentView addSubview:stop];
 NSTextField*info=[NSTextField wrappingLabelWithString:@"密码和指纹模板保存在当前用户的钥匙串中。匹配成功后仅尝试向锁屏密码框输入。首次使用需在系统设置中允许辅助功能。关闭窗口后仍在菜单栏运行。"];info.font=[NSFont systemFontOfSize:12];info.textColor=NSColor.secondaryLabelColor;info.frame=NSMakeRect(24,22,470,78);[self.window.contentView addSubview:info];
 self.item=[NSStatusBar.systemStatusBar statusItemWithLength:NSSquareStatusItemLength];self.stateItem.title=@"状态：已停止";self.item.button.title=@"";NSImage*icon=[NSImage imageWithSystemSymbolName:@"touchid" accessibilityDescription:@"指纹解锁"];if(!icon)icon=[NSImage imageWithSystemSymbolName:@"lock.fill" accessibilityDescription:@"指纹解锁"];icon.template=YES;icon.size=NSMakeSize(18,18);self.item.button.image=icon;NSMenu*m=[NSMenu new];self.stateItem=[[NSMenuItem alloc]initWithTitle:@"状态：已停止" action:nil keyEquivalent:@""];self.stateItem.enabled=NO;[m addItem:self.stateItem];[m addItem:NSMenuItem.separatorItem];NSMenuItem*show=[[NSMenuItem alloc]initWithTitle:@"显示窗口" action:@selector(show:) keyEquivalent:@""];show.target=self;[m addItem:show];NSMenuItem*pause=[[NSMenuItem alloc]initWithTitle:@"停止解锁" action:@selector(stop:) keyEquivalent:@""];pause.target=self;[m addItem:pause];[m addItem:NSMenuItem.separatorItem];NSMenuItem*quit=[[NSMenuItem alloc]initWithTitle:@"退出" action:@selector(quit:) keyEquivalent:@""];quit.target=self;[m addItem:quit];self.item.menu=m;[self show:nil];}
-(void)show:(id)sender{[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];}
-(BOOL)windowShouldClose:(NSWindow*)sender{[sender orderOut:nil];return NO;}
-(void)stop:(id)sender{self.armed=NO;cancelled=1;self.stateItem.title=@"状态：已停止";[self message:@"已停止；正在结束中的 USB 读取最多需要几秒。"];}
-(void)quit:(id)sender{self.armed=NO;cancelled=1;[NSApp terminate:nil];}
-(void)enroll:(id)sender {
    if(self.busy || self.armed) { [self message:@"请先停止当前操作，稍候再录入。"]; return; }
    NSMutableData *existing=loadSecret(@"fingerprints-v1",YES);
    NSAlert *alert=[NSAlert new];
    alert.messageText=existing?@"补充指腹覆盖范围":@"准备录入指纹";
    alert.informativeText=existing?@"补充录入会保留已有指纹。请继续使用原来那根手指，按提示向左、右、前、后逐步轻移，每次与上一次的位置略有重叠。补充成功的部分会逐次保存。":@"全程使用同一根手指。先录入指腹中心，再按提示向左、右、前、后逐步轻移。每次保持约3秒，看到松开提示后再抬起。录满8次后会开始保存，之后可以停止并在下次继续补充。";
    [alert addButtonWithTitle:existing?@"补充范围":@"开始"];
    if(existing)[alert addButtonWithTitle:@"重新录入"];
    [alert addButtonWithTitle:@"取消"];
    NSModalResponse choice=[alert runModal];
    if(choice!=(NSAlertFirstButtonReturn) && (!existing || choice!=NSAlertSecondButtonReturn)) { if(existing)wipe(existing.mutableBytes,existing.length);return; }
    BOOL extend=existing && choice==NSAlertFirstButtonReturn;
    if(!extend && existing){wipe(existing.mutableBytes,existing.length);existing=nil;}
    self.busy=YES;cancelled=0;self.phase=@"准备录入";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{ @autoreleasepool {
        NSString *result=@"录入未完成，请重试。";
        int retries=0,persisted=0,target=MaxPrints;
        clearPrints();close_sensor(&sensor);
        if(!open_sensor(&sensor)){result=@"无法打开指纹设备，请检查连接后重试。";goto done;}
        target=sensor.pid==0x0c1a?MaxPrints:MinPrints;
        if(extend) {
            if(!unpackPrints(existing)){result=@"已有指纹无法用于当前设备，请选择重新录入。";goto done;}
            persisted=printCount;
            if(printCount>=target){result=@"现有指纹已完成补充，可以点击“验证指纹”测试不同位置。";goto done;}
        }
        for(int i=3;i>0&&!cancelled;i--){report("请移开手指，等待背景采集。");sleep(1);}
        if(cancelled)goto done;
        if(!calibrate(&sensor)){result=@"背景采集失败，请移开手指后重试。";goto done;}
        while(printCount<target&&!cancelled) {
            int sample=printCount+1;
            NSString *guide=enrollmentGuide(printCount);
            dispatch_sync(dispatch_get_main_queue(),^{self.phase=[NSString stringWithFormat:@"录入 %d/%d · %@",sample,target,guide];});
            ElanpressFeatures *candidate=capture(&sensor);
            if(cancelled){elanpress_features_free(candidate);goto done;}
            if(!candidate){
                if(++retries>=6){result=[NSString stringWithFormat:@"第%d次未取得清晰指纹。已保存%d份，可以稍后继续补充。",sample,persisted];goto done;}
                report("这次没有采集成功，请松开手指后再试。");continue;
            }
            unsigned score=printCount?match(candidate,prints,printCount):0;
            printf("ENROLL sample=%d score=%u threshold=%d\n",sample,score,ELANPRESS_MATCH_MIN_PAIRS);
            if(sensor.pid==0x0c1a&&printCount>0&&score<ELANPRESS_MATCH_MIN_PAIRS) {
                if(printCount==1){elanpress_features_free(prints[0]);prints[0]=candidate;report("两次采集没有匹配上，请保持这次的位置，用同一根手指再按一次。");}
                else {elanpress_features_free(candidate);report("这次没有匹配上，请退回上次位置，缩小移动幅度再试。");}
                if(++retries>=6){result=[NSString stringWithFormat:@"第%d次未匹配上。已保存%d份，可以稍后继续补充。",sample,persisted];goto done;}
                continue;
            }
            prints[printCount++]=candidate;retries=0;
            if(printCount>=MinPrints) {
                NSData *data=packPrints();
                if(!data){result=@"未能生成指纹模板，请重试。";goto done;}
                OSStatus status=saveSecret(@"fingerprints-v1",data);
                if(status!=errSecSuccess){NSString *reason=CFBridgingRelease(SecCopyErrorMessageString(status,NULL));result=[NSString stringWithFormat:@"无法保存到钥匙串：%@",reason?:@"请允许钥匙串访问后重试。"];;goto done;}
                persisted=printCount;
            }
        }
        result=[NSString stringWithFormat:@"已保存%d份指纹。请点“验证指纹”，测试指腹中心和稍微偏移的位置。",persisted];
    done:
        if(existing)wipe(existing.mutableBytes,existing.length);
        if(cancelled)result=persisted?[NSString stringWithFormat:@"录入已停止，已保存%d份。下次可继续补充。",persisted]:@"录入已停止。";
        printf("ENROLL count=%d result=%s\n",persisted,result.UTF8String);
        close_sensor(&sensor);clearPrints();
        dispatch_async(dispatch_get_main_queue(),^{self.busy=NO;self.phase=@"";[self message:result];});
    }});
}
-(void)verify:(id)sender {
    if (self.busy || self.armed) { [self message:@"请先停止当前操作。"]; return; }
    self.busy = YES; cancelled = 0; self.phase = @"验证指纹";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{ @autoreleasepool {
        NSString *message = nil;
        clearPrints(); close_sensor(&sensor);
        if (!open_sensor(&sensor)) message = @"无法打开指纹设备，请检查连接后重试。";
        else if (!unpackPrints(loadSecret(@"fingerprints-v1",YES))) message = @"未找到适用于当前设备的指纹，请先录入。";
        else {
            ElanpressFeatures *features = capture(&sensor);
            if (features) {
                unsigned score = match(features,prints,printCount);
                printf("VERIFY score=%u threshold=%u matched=%d\n",score,ELANPRESS_MATCH_MIN_PAIRS,score>=ELANPRESS_MATCH_MIN_PAIRS);
                message = score>=ELANPRESS_MATCH_MIN_PAIRS ? @"指纹匹配。" : @"指纹不匹配，请用已录入的手指重试。";
                elanpress_features_free(features);
            } else message = cancelled ? @"验证已停止。" : @"未取得清晰指纹，请重试。";
        }
        close_sensor(&sensor); clearPrints();
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy=NO;self.phase=@"";[self message:message]; });
    }});
}
-(void)save:(id)sender{NSString*p=self.password.stringValue;if(!p.length||p.length>256){[self message:@"请输入本机登录密码（最多256个字符）。"];return;}if(self.busy||self.armed){[self message:@"请先停止当前操作。"];return;}self.busy=YES;[self message:@"正在本机验证密码…"];dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool{NSError*e=nil;ODNode*node=[ODNode nodeWithSession:ODSession.defaultSession type:kODNodeTypeLocalNodes error:&e];ODRecord*record=[node recordWithRecordType:kODRecordTypeUsers name:NSUserName() attributes:nil error:&e];BOOL valid=[record verifyPassword:p error:&e];OSStatus result=valid?saveSecret(@"login-password",[p dataUsingEncoding:NSUTF8StringEncoding]):errSecAuthFailed;dispatch_async(dispatch_get_main_queue(),^{self.busy=NO;self.password.stringValue=@"";[self message:result==errSecSuccess?@"密码已验证并存入钥匙串，可以启用锁屏解锁。":@"密码验证或钥匙串保存失败，请检查密码后重试。"];});}});}
-(void)arm:(id)sender{if(self.busy||self.armed){[self message:@"当前操作仍在运行。"];return;}NSDictionary*opts=@{(__bridge NSString*)kAXTrustedCheckOptionPrompt:@YES};if(!AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts)){[self message:@"请在系统设置 → 隐私与安全性 → 辅助功能中开启 ELAN指纹解锁，然后再点启用。"];[[NSWorkspace sharedWorkspace]openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"]];return;}NSMutableData*savedPassword=loadSecret(@"login-password",YES);NSMutableData*savedPrints=loadSecret(@"fingerprints-v1",YES);BOOL ready=savedPassword.length>0&&savedPrints.length>0;if(savedPassword)wipe(savedPassword.mutableBytes,savedPassword.length);if(savedPrints)wipe(savedPrints.mutableBytes,savedPrints.length);if(!ready){[self message:@"未能读取钥匙串中的密码或指纹，请允许钥匙串访问后重试。"];return;}self.busy=YES;self.armed=YES;cancelled=0;self.phase=@"";self.stateItem.title=@"状态：等待锁屏";[self message:@"已启动。按 Control + Command + Q 锁屏；点一下密码框后，用录入的手指轻触。"];
 dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool{BOOL episode=NO,attempted=NO;int failures=0;while(self.armed&&!cancelled){@autoreleasepool{if(!screenLocked()){if(episode){close_sensor(&sensor);memset(&sensor,0,sizeof(sensor));clearPrints();}episode=NO;attempted=NO;failures=0;usleep(300000);continue;}if(attempted){usleep(300000);continue;}if(!episode){episode=YES;if(!open_sensor(&sensor)||!unpackPrints(loadSecret(@"fingerprints-v1",NO))){report("读取传感器或钥匙串模板失败，请手动解锁后重新录入/启用。");break;}}if(!secureFocus()){report("请点一下锁屏密码框；未确认密码框时不会输入。");usleep(500000);continue;}dispatch_async(dispatch_get_main_queue(),^{self.stateItem.title=@"状态：请轻触";});ElanpressFeatures*f=capture(&sensor);if(!f){if(cancelled)break;report("未取得合格指纹，稍后重试。");continue;}unsigned score=match(f,prints,printCount);elanpress_features_free(f);if(score<ELANPRESS_MATCH_MIN_PAIRS){failures++;report("指纹不匹配，请松开后再试。");if(failures>=4){attempted=YES;report("本次锁屏已达到4次失败，请手动输入密码。");}continue;}if(!secureFocus()){report("指纹匹配，但锁屏密码框已改变；未输入。");continue;}
 NSMutableData*bytes=loadSecret(@"login-password",NO);if(!bytes){report("钥匙串密码不可读取，请手动解锁后重新保存密码。");attempted=YES;continue;}NSString*p=[[NSString alloc]initWithData:bytes encoding:NSUTF8StringEncoding];BOOL sent=p&&self.armed&&!cancelled&&typePassword(p);wipe(bytes.mutableBytes,bytes.length);p=nil;attempted=YES;if(sent){for(int i=0;i<30&&screenLocked()&&self.armed;i++)usleep(200000);report(screenLocked()?"已尝试输入，但系统尚未解锁。请用密码登录后查看状态。":"本次指纹解锁成功。");}else report("指纹匹配；系统未允许输入或焦点变化，请手动解锁。");}}
 close_sensor(&sensor);memset(&sensor,0,sizeof(sensor));clearPrints();dispatch_async(dispatch_get_main_queue(),^{self.busy=NO;self.armed=NO;self.stateItem.title=@"状态：已停止";});}});}
@end
#include "ElanAuthBroker.inc"
#include "ElanCaptureStudy.inc"
static int systemCapabilities(void) {
    LAContext *context=[LAContext new];NSError *error=nil;
    BOOL available=[context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    printf("SYSTEM_BIOMETRICS available=%d type=%ld error=%ld\n",available,(long)context.biometryType,(long)error.code);
    NSMutableData *data=loadSecret(@"fingerprints-v1",NO);
    printf("TEMPLATE_ACCESS interactive=0 readable=%d\n",data!=nil);
    if(data)wipe(data.mutableBytes,data.length);
    return 0;
}
#ifndef ELAN_NO_APP_MAIN
int main(int argc,char**argv){@autoreleasepool{setbuf(stdout,NULL);if(argc==2&&!strcmp(argv[1],"--self-test"))return self_test()|template_self_test()|authPeerSelfTest()|captureStudySelfTest();if(argc==2&&!strcmp(argv[1],"--auth-broker"))return authBrokerMain();if(argc==2&&!strcmp(argv[1],"--prepare-auth-broker"))return authBrokerPrepare();if(argc==2&&!strcmp(argv[1],"--capture-study"))return captureStudyMain();if(argc==2&&!strcmp(argv[1],"--system-capabilities"))return systemCapabilities();[NSApplication sharedApplication];NSApp.activationPolicy=NSApplicationActivationPolicyAccessory;Delegate*d=[Delegate new];NSApp.delegate=d;[NSApp run];}return 0;}
#endif
