#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <stdint.h>
int main(void) { @autoreleasepool {
 setbuf(stdout, NULL);
 char build[64]={}; size_t n=sizeof(build);
 if(sysctlbyname("kern.osversion",build,&n,NULL,0)||strcmp(build,"24H32"))return 2;
 const char *images[]={"LocalAuthenticationCore","BiometricSupport"};
 for(int i=0;i<2;i++){
 NSString *path=[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/%s.framework/%s",images[i],images[i]];
 if(!dlopen(path.UTF8String,RTLD_LAZY|RTLD_LOCAL)) {printf("LOAD_ERROR %s\n",images[i]);return 3;}
 }
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fb0ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fb0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62a18ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62a18 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62a88ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62a88 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62a88ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62a88 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62468ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62468 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fd8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fd8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fa8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fa8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fa8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fa8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fd0ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fd0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fb8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fb8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fc0ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fc0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a624e8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a624e8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_setup"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8191ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fa8ULL+delta);
 printf("SEL LACBiometryHelper::_setup 0x7ffc40a62fa8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_shouldRetryAvailableDevices"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d85afULL;
 SEL ref=*(SEL *)(0x7ffc40a62fe0ULL+delta);
 printf("SEL LACBiometryHelper::_shouldRetryAvailableDevices 0x7ffc40a62fe0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_shouldRetryAvailableDevices"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d85afULL;
 SEL ref=*(SEL *)(0x7ffc40a62fe8ULL+delta);
 printf("SEL LACBiometryHelper::_shouldRetryAvailableDevices 0x7ffc40a62fe8 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("_shouldRetryAvailableDevices"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d85afULL;
 SEL ref=*(SEL *)(0x7ffc40a62f80ULL+delta);
 printf("SEL LACBiometryHelper::_shouldRetryAvailableDevices 0x7ffc40a62f80 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("LACBiometryHelper"),sel_registerName("deviceHasBiometryWithError:"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffc0c6d8e13ULL;
 SEL ref=*(SEL *)(0x7ffc40a62fa0ULL+delta);
 printf("SEL LACBiometryHelper::deviceHasBiometryWithError: 0x7ffc40a62fa0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("BiometricKitXPCServer"),sel_registerName("getBiometryAvailability:forUser:withClient:"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffa016b87c9ULL;
 SEL ref=*(SEL *)(0x7ffa403154c0ULL+delta);
 printf("SEL BiometricKitXPCServer::getBiometryAvailability:forUser:withClient: 0x7ffa403154c0 %s\n",sel_getName(ref));}
 {Method m=class_getInstanceMethod(objc_getClass("BiometricKitXPCServer"),sel_registerName("getBiometryAvailability:forUser:withClient:"));
 if(!m)return 4; intptr_t delta=(intptr_t)method_getImplementation(m)-0x7ffa016b87c9ULL;
 SEL ref=*(SEL *)(0x7ffa403151e0ULL+delta);
 printf("SEL BiometricKitXPCServer::getBiometryAvailability:forUser:withClient: 0x7ffa403151e0 %s\n",sel_getName(ref));}

 Class helper=objc_getClass("LACBiometryHelper");
 const uint64_t refs[]={0x7FFC40A63050ULL,0x7FFC40A63008ULL,0x7FFC40A63058ULL,0x7FFC40A63060ULL};
 intptr_t delta=(intptr_t)method_getImplementation(class_getInstanceMethod(helper,sel_registerName("_setup")))-0x7FFC0C6D8191ULL;
 for(unsigned i=0;i<4;i++)printf("LAC_PAIRING_SELECTOR %s\n",sel_getName(*(SEL *)(refs[i]+delta)));
 const char *names[]={"LACBiometryHelper","BKAccessory","BiometricKitAccessory"};
 for(unsigned i=0;i<3;i++){
 Class cls=objc_getClass(names[i]); printf("PAIRING_CLASS %s present=%d\n",names[i],cls!=Nil);
 for(int meta=0;meta<2;meta++){
 unsigned count=0; Method *methods=class_copyMethodList(meta?object_getClass(cls):cls,&count);
 for(unsigned j=0;j<count;j++){
 const char *name=sel_getName(method_getName(methods[j]));
 if(i || strstr(name,"ccessor") || strstr(name,"nternal") || strstr(name,"aired"))
 printf("PAIRING_METHOD %s %c%s %s\n",names[i],meta?'+':'-',name,method_getTypeEncoding(methods[j]));
 }free(methods);
 }
 }
puts("LAC_METADATA_DONE authentication_requested=0 process_state_changed=0"); return 0;}}
