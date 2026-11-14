#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static NSData *readOwnMemory(uintptr_t address, size_t length) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    mach_vm_size_t copied = 0;
    if (mach_vm_read_overwrite(mach_task_self(), address, length, (mach_vm_address_t)data.mutableBytes, &copied) || copied != length) return nil;
    return data;
}

int main(void) {
    @autoreleasepool {
        const char *path = "/System/Library/PrivateFrameworks/BiometricKitUI.framework/BiometricKitUI";
        if (!dlopen(path, RTLD_LAZY | RTLD_LOCAL)) return 2;
        Class cls = NSClassFromString(@"BKUIFingerprintEnrollViewController");
        if (!cls) return 3;
        NSMutableDictionary *symbols = [NSMutableDictionary dictionary];
        NSMutableArray *addresses = [NSMutableArray array];
        unsigned classes = 0;
        const char **names = objc_copyClassNamesForImage(class_getImageName(cls), &classes);
        Dl_info info = {0};
        for (unsigned i = 0; i < classes; i++) {
            Class current = objc_getClass(names[i]);
            for (int meta = 0; meta < 2; meta++) {
                unsigned count = 0;
                Method *methods = class_copyMethodList(meta ? object_getClass(current) : current, &count);
                for (unsigned j = 0; j < count; j++) {
                    uintptr_t address = (uintptr_t)method_getImplementation(methods[j]);
                    [addresses addObject:@(address)];
                    symbols[@(address).stringValue] = [NSString stringWithFormat:@"%c[%s %s]", meta ? '+' : '-', names[i], sel_getName(method_getName(methods[j]))];
                    if (!info.dli_fbase) dladdr((void *)address, &info);
                }
                free(methods);
            }
        }
        free(names);
        if (!info.dli_fbase) return 4;
        [addresses sortUsingSelector:@selector(compare:)];
        const struct mach_header_64 *header = info.dli_fbase;
        if (header->magic != MH_MAGIC_64) return 5;
        intptr_t slide = 0;
        uintptr_t command = (uintptr_t)(header + 1);
        for (unsigned i = 0; i < header->ncmds; i++) {
            const struct load_command *load = (void *)command;
            if (load->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *segment = (void *)command;
                if (!strcmp(segment->segname, "__TEXT")) slide = (uintptr_t)header - segment->vmaddr;
            }
            command += load->cmdsize;
        }
        NSMutableDictionary *references = [NSMutableDictionary dictionary];
        NSMutableArray *sections = [NSMutableArray array];
        NSMutableDictionary *ivars = [NSMutableDictionary dictionary];
        unsigned ivarCount = 0;
        Ivar *ivarList = class_copyIvarList(cls, &ivarCount);
        for (unsigned i = 0; i < ivarCount; i++) {
            NSString *symbol = [NSString stringWithFormat:@"OBJC_IVAR_$_%s.%s", class_getName(cls), ivar_getName(ivarList[i])];
            void *address = dlsym(RTLD_DEFAULT, symbol.UTF8String);
            ivars[@(ivar_getOffset(ivarList[i])).stringValue] = @(ivar_getName(ivarList[i]));
            if (address) references[@((uintptr_t)address).stringValue] = symbol;
        }
        free(ivarList);
        command = (uintptr_t)(header + 1);
        for (unsigned i = 0; i < header->ncmds; i++) {
            const struct load_command *load = (void *)command;
            if (load->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *segment = (void *)command;
                const struct section_64 *section = (void *)(segment + 1);
                for (unsigned j = 0; j < segment->nsects; j++, section++) {
                    uintptr_t address = section->addr + slide;
                    if ((!strcmp(section->sectname, "__const") || !strcmp(section->sectname, "__objc_ivar")) && section->size < 1024 * 1024) {
                        NSData *data = readOwnMemory(address, section->size);
                        if (data) [sections addObject:@{@"name": @(section->sectname), @"address": @(address), @"bytes": [data base64EncodedStringWithOptions:0]}];
                    }
                    if (!strcmp(section->sectname, "__objc_selrefs")) {
                        NSData *data = readOwnMemory(address, section->size);
                        const SEL *values = data.bytes;
                        for (NSUInteger k = 0; k < data.length / sizeof(SEL); k++) {
                            const char *name = sel_getName(values[k]);
                            if (name) references[@(address + k * sizeof(SEL)).stringValue] = [NSString stringWithFormat:@"selector:%s", name];
                        }
                    } else if (!strcmp(section->sectname, "__cfstring")) {
                        NSData *data = readOwnMemory(address, section->size);
                        const uintptr_t *values = data.bytes;
                        for (NSUInteger k = 0; k + 3 < data.length / sizeof(uintptr_t); k += 4) {
                            if (values[k + 3] > 512 || (values[k + 1] & 0x10)) continue;
                            NSData *text = readOwnMemory(values[k + 2], values[k + 3]);
                            NSString *string = text ? [[NSString alloc] initWithData:text encoding:NSUTF8StringEncoding] : nil;
                            if (string) references[@(address + k * sizeof(uintptr_t)).stringValue] = [@"string:" stringByAppendingString:string];
                        }
                    }
                }
            }
            command += load->cmdsize;
        }
        NSArray *selected = @[@"_startExtendEnrollOperation", @"extendEnroll:hasUpdated:", @"_showEnrollmentPhaseTwo",
            @"_finishEnrollmentPhaseTwo", @"_startEnrollmentMatch", @"enrollResult:", @"enrollOperation:finishedWithIdentity:",
            @"handleEnrollProgress:", @"_startInitialTutorial:", @"tutorialContinuePressed:", @"operation:presenceStateChanged:"];
        selected = [selected arrayByAddingObjectsFromArray:@[@"viewDidLoad", @"loadView", @"setProperty:forKey:", @"operation:finishedWithReason:"]];
        selected = [selected arrayByAddingObjectsFromArray:@[@"initializeMesaEnrollContainer", @"initPromptMessage", @"viewWillAppear", @"_resetUI"]];
        NSMutableArray *functions = [NSMutableArray array];
        for (NSString *name in selected) {
            Method method = class_getInstanceMethod(cls, NSSelectorFromString(name));
            if (!method) continue;
            uintptr_t start = (uintptr_t)method_getImplementation(method), end = start + 8192;
            for (NSNumber *number in addresses) if (number.unsignedLongLongValue > start) { end = MIN(end, number.unsignedLongLongValue); break; }
            NSData *data = readOwnMemory(start, end - start);
            if (!data) return 6;
            [functions addObject:@{@"name": name, @"address": @(start), @"bytes": [data base64EncodedStringWithOptions:0]}];
        }
        NSDictionary *result = @{@"functions": functions, @"symbols": symbols, @"references": references, @"sections": sections, @"ivars": ivars,
            @"controllers_created": @0, @"windows_opened": @0, @"system_service_changed": @0};
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
        fwrite(json.bytes, 1, json.length, stdout); fputc('\n', stdout);
    }
    return 0;
}
