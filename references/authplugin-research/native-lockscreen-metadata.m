#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>

int main(void) {
    @autoreleasepool {
        char build[64] = {0};
        size_t size = sizeof(build);
        if (sysctlbyname("kern.osversion", build, &size, NULL, 0) || strcmp(build, "24H32")) return 2;
        NSArray<NSString *> *frameworks = @[@"CommonAuth", @"LoginUIKit", @"UAUPlugin", @"login", @"LocalAuthenticationCore"];
        for (NSString *name in frameworks) {
            NSString *path = [NSString stringWithFormat:@"/System/Library/PrivateFrameworks/%@.framework/%@", name, name];
            if (!dlopen(path.UTF8String, RTLD_LAZY | RTLD_LOCAL)) return 3;
        }
        NSMutableArray *classes = [NSMutableArray array];
        NSMutableArray *images = [NSMutableArray array];
        for (uint32_t image = 0; image < _dyld_image_count(); image++) {
            const char *imageName = _dyld_get_image_name(image);
            BOOL selected = NO;
            for (NSString *name in frameworks) {
                NSString *part = [NSString stringWithFormat:@"/%@.framework/", name];
                if (strstr(imageName, part.UTF8String)) selected = YES;
            }
            if (!selected) continue;
            unsigned count = 0;
            const char **names = objc_copyClassNamesForImage(imageName, &count);
            [images addObject:@{@"path": @(imageName), @"class_count": @(count)}];
            for (unsigned i = 0; i < count; i++) {
                if (strstr(imageName, "/LocalAuthenticationCore.framework/") && !strstr(names[i], "Hint")) continue;
                Class cls = objc_getClass(names[i]);
                NSMutableArray *methods = [NSMutableArray array];
                NSMutableArray *ivars = [NSMutableArray array];
                for (int meta = 0; meta < 2; meta++) {
                    unsigned methodCount = 0;
                    Method *list = class_copyMethodList(meta ? object_getClass(cls) : cls, &methodCount);
                    for (unsigned j = 0; j < methodCount; j++) {
                        [methods addObject:@{@"name": @(sel_getName(method_getName(list[j]))),
                            @"class_method": @(meta != 0), @"encoding": @(method_getTypeEncoding(list[j]) ?: "")}];
                    }
                    free(list);
                }
                unsigned ivarCount = 0;
                Ivar *list = class_copyIvarList(cls, &ivarCount);
                for (unsigned j = 0; j < ivarCount; j++) {
                    [ivars addObject:@{@"name": @(ivar_getName(list[j])),
                        @"encoding": @(ivar_getTypeEncoding(list[j]) ?: ""), @"offset": @(ivar_getOffset(list[j]))}];
                }
                free(list);
                [classes addObject:@{@"name": @(names[i]), @"methods": methods, @"ivars": ivars}];
            }
            free(names);
        }
        NSDictionary *result = @{@"build": @(build), @"classes": classes, @"images": images,
            @"instances_created": @NO, @"authentication_requested": @NO,
            @"other_process_memory_read": @NO, @"keychain_accessed": @NO};
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:NULL];
        if (!json) return 4;
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
    }
    return 0;
}
