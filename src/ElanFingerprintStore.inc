// Shared fingerprint template format and Keychain storage. Include after elan_match_test.c.
#include "ElanTemplateFormat.h"
static void wipe(void*p,size_t n){volatile unsigned char*v=p;while(n--)*v++=0;}
enum { MaxPrints=ElanTemplateMaximumSamples, MinPrints=ElanTemplateMinimumSamples };
static ElanpressFeatures *prints[MaxPrints]={0};
static int printCount=0;
static Sensor sensor={0};
static NSString *const Service=@"io.github.hackintosh-tools.elan-unlock";
static NSMutableDictionary*query(NSString*name){return [@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:Service,(__bridge id)kSecAttrAccount:name} mutableCopy];}
static OSStatus saveSecret(NSString*name,NSData*data){NSMutableDictionary*q=query(name);OSStatus s=SecItemUpdate((__bridge CFDictionaryRef)q,(__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});if(s==errSecItemNotFound){q[(__bridge id)kSecValueData]=data;q[(__bridge id)kSecAttrLabel]=@"ELAN 指纹解锁";s=SecItemAdd((__bridge CFDictionaryRef)q,NULL);}printf("KEYCHAIN save account=%s status=%d\n",name.UTF8String,(int)s);return s;}
static NSMutableData*loadSecret(NSString*name,BOOL interactive){NSMutableDictionary*q=query(name);q[(__bridge id)kSecReturnData]=@YES;q[(__bridge id)kSecMatchLimit]=(__bridge id)kSecMatchLimitOne;if(!interactive)q[(__bridge id)kSecUseAuthenticationUI]=(__bridge id)kSecUseAuthenticationUIFail;CFTypeRef d=NULL;OSStatus s=SecItemCopyMatching((__bridge CFDictionaryRef)q,&d);if(s!=errSecSuccess||!d){printf("KEYCHAIN read account=%s interactive=%d status=%d\n",name.UTF8String,interactive,(int)s);if(d)CFRelease(d);return nil;}NSData*data=CFBridgingRelease(d);return [data mutableCopy];}
static void clearPrints(void){for(int i=0;i<MaxPrints;i++){if(prints[i]){wipe(prints[i]->kp,prints[i]->n*sizeof(ElanpressKeypoint));elanpress_features_free(prints[i]);prints[i]=NULL;}}printCount=0;}
static NSData *packPrints(void) {
    if (!sensor.bg || sensor.w <= 0 || sensor.hgt <= 0 || printCount<MinPrints || printCount>MaxPrints) return nil;
    NSMutableArray *items = [NSMutableArray array];
    for (int i = 0; i < printCount; ++i) {
        if (!prints[i]) return nil;
        [items addObject:[NSData dataWithBytes:prints[i]->kp length:prints[i]->n * sizeof(ElanpressKeypoint)]];
    }
    NSDictionary *record = @{@"schema": @3, @"pid": @(sensor.pid),
        @"width": @(sensor.w), @"height": @(sensor.hgt), @"prints": items,
        @"background": [NSData dataWithBytes:sensor.bg length:(size_t)sensor.w * sensor.hgt * 2]};
    return [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
}

static BOOL unpackPrints(NSData *data) {
    NSDictionary *record = ElanDecodeTemplate(data, sensor.pid, sensor.w, sensor.hgt);
    if (!record || !sensor.bg) return NO;
    id items = record[@"prints"], background = record[@"background"];
    size_t frameBytes = (size_t)sensor.w * sensor.hgt * 2;
    clearPrints();
    printCount=(int)[items count];
    for (int i = 0; i < printCount; ++i) {
        NSData *item = items[i];
        prints[i] = calloc(1, sizeof(ElanpressFeatures));
        if (!prints[i]) { clearPrints(); return NO; }
        prints[i]->n = (guint)(item.length / sizeof(ElanpressKeypoint));
        prints[i]->kp = malloc(item.length);
        if (!prints[i]->kp) { clearPrints(); return NO; }
        memcpy(prints[i]->kp, item.bytes, item.length);
    }
    memcpy(sensor.bg, [background bytes], frameBytes);
    return YES;
}

static int template_self_test(void) {
    int ok=1;
    const int cases[][4]={{0x0c1a,144,64,8},{0x0c1a,144,64,24},{0x0c6e,150,52,8}};
    for(int c=0;c<3;c++) {
        sensor.pid=cases[c][0]; sensor.w=cases[c][1]; sensor.hgt=cases[c][2]; printCount=cases[c][3];
        int count=printCount;
        size_t n=(size_t)sensor.w*sensor.hgt;
        sensor.bg=calloc(n,sizeof(*sensor.bg));
        for(size_t i=0;i<n;i++)sensor.bg[i]=(unsigned short)(i%16384);
        for(int i=0;i<count;i++) {
            prints[i]=calloc(1,sizeof(*prints[i])); prints[i]->n=ELANPRESS_MATCH_MIN_PAIRS;
            prints[i]->kp=calloc(prints[i]->n,sizeof(*prints[i]->kp));
            for(guint j=0;j<prints[i]->n;j++){prints[i]->kp[j].x=j;prints[i]->kp[j].y=i;prints[i]->kp[j].scale=1;}
        }
        NSData *packed=packPrints();
        clearPrints(); memset(sensor.bg,0,n*2);
        int passed=unpackPrints(packed)&&printCount==count&&sensor.bg[n-1]==(n-1)%16384&&prints[count-1]->kp[3].y==count-1;
        NSMutableDictionary *legacy=[[NSPropertyListSerialization propertyListWithData:packed options:NSPropertyListMutableContainers format:NULL error:nil] mutableCopy];
        if(count==8) {
            legacy[@"schema"]=sensor.pid==0x0c6e?@1:@2;
            if(sensor.pid==0x0c6e)[legacy removeObjectForKey:@"pid"];
            NSData *old=[NSPropertyListSerialization dataWithPropertyList:legacy format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
            clearPrints(); passed&=unpackPrints(old)&&printCount==8;
        }
        sensor.w++;passed&=!unpackPrints(packed);sensor.w--;
        legacy[@"schema"]=@3;legacy[@"pid"]=@(sensor.pid);
        NSMutableArray *oversized=[legacy[@"prints"] mutableCopy];
        while(oversized.count<=MaxPrints)[oversized addObject:oversized[0]];
        legacy[@"prints"]=oversized;
        passed&=!unpackPrints([NSPropertyListSerialization dataWithPropertyList:legacy format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil]);
        printf("Template %04x %dx%d count=%d migration/bounds=%s\n",sensor.pid,sensor.w,sensor.hgt,count,passed?"pass":"fail");
        ok&=passed;clearPrints();close_sensor(&sensor);
    }
    return ok?0:1;
}
