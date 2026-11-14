#import "ElanAuthPlugin.m"

@interface ElanAuthPreviewDelegate:NSObject<NSApplicationDelegate,NSWindowDelegate>
@property NSWindow *window;
@property ElanAuthContent *view;
@end
static ElanAuthPreviewDelegate *previewDelegate;
static OSStatus previewResult(AuthorizationEngineRef engine,AuthorizationResult result){printf("Preview callback: %s\n",result==kAuthorizationResultAllow?"credentials collected":result==kAuthorizationResultUserCanceled?"cancelled":"denied");return noErr;}
static OSStatus previewContext(AuthorizationEngineRef engine,AuthorizationString key,AuthorizationContextFlags flags,const AuthorizationValue *value){return noErr;}
static OSStatus previewDeactivate(AuthorizationEngineRef engine){return noErr;}
@implementation ElanAuthPreviewDelegate
-(void)applicationDidFinishLaunching:(NSNotification *)notification {
    static AuthorizationCallbacks callbacks={.version=kAuthorizationCallbacksVersion,.SetResult=previewResult,.SetContextValue=previewContext,.DidDeactivate=previewDeactivate};
    self.view=[[ElanAuthContent alloc]initWithCallbacks:&callbacks andEngineRef:(AuthorizationEngineRef)1];
    self.window=[[NSWindow alloc]initWithContentRect:NSMakeRect(0,0,454,308) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"ELAN 系统认证视图预览";self.window.delegate=self;self.window.releasedWhenClosed=NO;
    NSView *content=[self.view viewForType:SFViewTypeCredentials];content.frameOrigin=NSMakePoint(30,65);
    [self.window.contentView addSubview:content];
    NSButton *cancel=[NSButton buttonWithTitle:@"取消" target:self action:@selector(cancel:)];cancel.frame=NSMakeRect(236,18,88,32);cancel.keyEquivalent=@"\e";
    NSButton *next=[NSButton buttonWithTitle:@"继续" target:self action:@selector(next:)];next.frame=NSMakeRect(336,18,88,32);next.keyEquivalent=@"\r";
    [self.window.contentView addSubview:cancel];[self.window.contentView addSubview:next];
    [self.view willActivateWithUser:nil];[self.window center];[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
}
-(void)cancel:(id)sender{[self.view buttonPressed:SFButtonTypeCancel];[NSApp terminate:nil];}
-(void)next:(id)sender{[self.view buttonPressed:SFButtonTypeOK];}
-(BOOL)windowShouldClose:(id)sender{[self cancel:nil];return YES;}
@end
int main(void){@autoreleasepool{[NSApplication sharedApplication];NSApp.activationPolicy=NSApplicationActivationPolicyRegular;previewDelegate=[ElanAuthPreviewDelegate new];NSApp.delegate=previewDelegate;[NSApp run];}return 0;}
