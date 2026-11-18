#import "AccessoryDiscovery.h"
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>
#include "../kernel-provider/NativePlatformCache.h"
#include "../kernel-provider/NativeSettingsRoute.h"
extern "C" int __shared_region_check_np(uint64_t *);
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <unistd.h>

@interface NSObject (ELANSettingsDevice)
+ (NSArray *)availableDevices;
+ (id)deviceWithDescriptor:(id)descriptor error:(NSError **)error;
- (NSArray *)connectedAccessoriesWithError:(NSError **)error;
- (id)createEnrollOperationWithError:(NSError **)error;
- (void)setUserID:(unsigned int)userID;
- (void)setCredentialSet:(NSData *)credentialSet;
- (BOOL)startWithError:(NSError **)error;
@end

struct OwnRegion {
    vm_prot_t protection;
    vm_prot_t maximum;
    unsigned share;
};

static bool regionFor(uintptr_t address, size_t size, OwnRegion &out) {
    natural_t depth = 0;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        mach_vm_address_t base = address;
        mach_vm_size_t length = 0;
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (mach_vm_region_recurse(mach_task_self(), &base, &length, &depth,
                reinterpret_cast<vm_region_recurse_info_t>(&info), &count)) return false;
        if (info.is_submap) { ++depth; continue; }
        if (base > address || size > length || address - base > length - size) return false;
        out = {info.protection, info.max_protection, info.share_mode};
        return true;
    }
    return false;
}

@interface LAContext (ELANExternalContext)
- (NSData *)externalizedContext;
@end

// Exercise Apple's start call with a real, unevaluated context. This reader has no Apple enrollment entitlement.
static BOOL checkUnprivilegedStart(id operation, id device, NSMutableDictionary *report) {
    LAContext *context = [LAContext new];
    context.interactionNotAllowed = YES;
    @try {
        NSData *external = [context respondsToSelector:@selector(externalizedContext)] ? [context externalizedContext] : nil;
        if (external.length != 16) return NO;
        [operation setUserID:getuid()];
        [operation setCredentialSet:external];
        NSError *error = nil;
        BOOL started = [operation startWithError:&error];
        report[@"start_returned"] = @(started);
        report[@"start_error_domain"] = error.domain ?: @"";
        report[@"start_error_code"] = @(error.code);
        NSError *readError = nil;
        NSArray *items = [device connectedAccessoriesWithError:&readError];
        BOOL connected = !readError && items.count == 1 &&
            [[items.firstObject valueForKey:@"name"] isEqual:@"ELAN 0c1a"];
        report[@"same_connection_usable_after_denial"] = @(connected);
        return !started && [error.domain isEqual:@"com.apple.BiometricKit"] && connected;
    } @finally {
        [context invalidate];
    }
}

// 24H32 Intel uses a CFConstantString in a read-only, copy-on-write data page
// for the type-1 NSXPCConnection. Keep its length, type and ownership unchanged.
struct OwnServiceName {
    uintptr_t slot = 0;
    uintptr_t original = 0;
    mach_vm_address_t replacement = 0;
    mach_vm_address_t page = 0;
    mach_vm_size_t size = 0;

    bool replace(const char *service, const NativeSettingsEndpoint::Location &location) {
        constexpr size_t count = sizeof(NativeSettingsEndpoint::appleName);
        if (!service || strlen(service) != count - 1) return false;
        slot = location.slot;
        original = location.original;
        OwnRegion region{};
        if (!regionFor(slot,sizeof(uintptr_t),region) || region.protection != VM_PROT_READ ||
            region.maximum != (VM_PROT_READ | VM_PROT_WRITE) || region.share != SM_COW) return false;
        size = static_cast<mach_vm_size_t>(getpagesize());
        page = slot & ~(size-1);
        if (mach_vm_allocate(mach_task_self(), &replacement, size, VM_FLAGS_ANYWHERE)) return false;
        memcpy(reinterpret_cast<void *>(replacement), service, count);
        OwnRegion storage{};
        if (mach_vm_protect(mach_task_self(),replacement,size,true,VM_PROT_READ) ||
            !regionFor(replacement,size,storage) || storage.protection != VM_PROT_READ ||
            storage.maximum != VM_PROT_READ ||
            mach_vm_protect(mach_task_self(),page,size,false,VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE)) {
            releaseStorage();
            return false;
        }
        uintptr_t expected = original;
        bool changed = __atomic_compare_exchange_n(reinterpret_cast<uintptr_t *>(slot), &expected, replacement,
                                                   false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (!changed) releaseStorage();
        if (mach_vm_protect(mach_task_self(),page,size,false,VM_PROT_READ)) {
            if (changed) restore();
            return false;
        }
        return changed;
    }

    bool restore() {
        auto *ptr = reinterpret_cast<uintptr_t *>(slot);
        if (mach_vm_protect(mach_task_self(),page,size,false,VM_PROT_READ | VM_PROT_WRITE)) return false;
        uintptr_t expected = replacement;
        bool changed = __atomic_compare_exchange_n(ptr,&expected,original,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
        if (mach_vm_protect(mach_task_self(),page,size,false,VM_PROT_READ)) return false;
        OwnRegion region{};
        return changed && __atomic_load_n(ptr,__ATOMIC_SEQ_CST) == original &&
               regionFor(slot,sizeof(*ptr),region) && region.protection == VM_PROT_READ && releaseStorage();
    }

private:
    bool releaseStorage() {
        if (mach_vm_deallocate(mach_task_self(),replacement,size)) return false;
        replacement = 0;
        return true;
    }
};

struct OwnCache {
    uint64_t function;
    NativePlatformCacheLocation bytes;
};

static int readMapped(void *, uint64_t address, void *out, size_t bytes) {
    mach_vm_size_t copied=0;
    return mach_vm_read_overwrite(mach_task_self(),address,bytes,reinterpret_cast<mach_vm_address_t>(out),&copied) ||
           copied!=bytes ? -1 : 0;
}

struct ReaderMap {
    OwnServiceName &route;
    CurrentCopyinSample::Reader reader() const { return {nullptr,readMapped}; }
    bool permitted() const { return true; }
    bool cowSlot(uint64_t slot) const {
        OwnRegion r{};
        return regionFor(slot,8,r) && r.protection==VM_PROT_READ && r.maximum==3 && r.share==SM_COW;
    }
    bool readOnlySlot(uint64_t slot) const {
        OwnRegion r{};
        return regionFor(slot,8,r) && r.protection==VM_PROT_READ && r.maximum==3;
    }
    bool writableData(uint64_t address) const {
        OwnRegion r{};
        return regionFor(address,2,r) && r.protection==3 && r.maximum==3 && r.share==SM_COW;
    }
    bool allocate(uint64_t &storage) const {
        if (mach_vm_allocate(mach_task_self(),&route.replacement,4096,VM_FLAGS_ANYWHERE)) return false;
        storage=route.replacement;
        return true;
    }
    bool release(uint64_t address) const {
        if (mach_vm_deallocate(mach_task_self(),address,4096)) return false;
        route.replacement=0;
        return true;
    }
    bool write(uint64_t address,const uint8_t *data,size_t n) const {
        memcpy(reinterpret_cast<void *>(address),data,n);
        return true;
    }
    bool seal(uint64_t address) const {
        OwnRegion r{};
        return !mach_vm_protect(mach_task_self(),address,4096,true,VM_PROT_READ) &&
               regionFor(address,4096,r) && r.protection==VM_PROT_READ && r.maximum==VM_PROT_READ;
    }
    bool makeCopyWritable(uint64_t page) const { return !mach_vm_protect(mach_task_self(),page,4096,false,VM_PROT_COPY|3); }
    bool protectSlot(uint64_t page) const { return !mach_vm_protect(mach_task_self(),page,4096,false,VM_PROT_READ); }
    bool storePointer(uint64_t slot,uint64_t value) const {
        __atomic_store_n(reinterpret_cast<uint64_t *>(slot),value,__ATOMIC_SEQ_CST);
        return true;
    }
};

static bool ownWritable(void *ctx, uint64_t address, size_t n) {
    auto &own = *static_cast<OwnCache *>(ctx);
    if (address != own.bytes.checked || n != 2) return false;
    OwnRegion region{};
    return regionFor(address, n, region) && (region.protection & VM_PROT_WRITE) &&
           !(region.protection & VM_PROT_EXECUTE) && (region.share == SM_COW || region.share == SM_PRIVATE);
}

static int ownRead(void *ctx, uint64_t address, void *out, size_t n) {
    auto &own = *static_cast<OwnCache *>(ctx);
    if (!(address == own.function && n == 0x245) && !(address == own.bytes.checked && n == 2)) return -1;
    memcpy(out, reinterpret_cast<const void *>(address), n);
    return 0;
}

static int ownWrite(void *ctx, uint64_t address, const void *data, size_t n) {
    if (!ownWritable(ctx, address, n)) return -1;
    memcpy(reinterpret_cast<void *>(address), data, n);
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2 || getuid() == 0 || geteuid() != getuid()) return 2;
        bool checkDenial = false, coldStart = false;
        for (int i = 2; i < argc; ++i) {
            if (!checkDenial && !strcmp(argv[i], "--check-enrollment-denial")) checkDenial = true;
            else if (!coldStart && !strcmp(argv[i], "--cold-start")) coldStart = true;
            else return 2;
        }
        NSString *endpoint = [NSString stringWithUTF8String:argv[1]];
        char build[32] = {};
        size_t length = sizeof(build);
        if (!ELANDiscoveryNameAllowed(endpoint) || sysctlbyname("kern.osversion",build,&length,nullptr,0) ||
            strcmp(build,"24H32")) return 2;
        if (!coldStart && (ELANReadDiscovery(endpoint) != 0 || ![ELANSystemTouchIDPlatform() isEqual:@NO] ||
                           ![ELANSystemDeviceCount() isEqual:@0])) return 2;
        constexpr const char *frameworkPath = "/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit";
        void *prior = dlopen(frameworkPath, RTLD_NOLOAD | RTLD_LAZY);
        const bool loadedAtEntry = prior != nullptr;
        if (prior) dlclose(prior);
        uint64_t base = 0;
        NativeSettingsEndpoint::Location location{};
        if (__shared_region_check_np(&base) || !NativeSettingsEndpoint::locate({nullptr,readMapped},base,location)) {
            fputs("Unsupported BiometricKit endpoint layout in the shared cache\n",stderr);
            return 2;
        }
        OwnCache own{location.platformFunction,{}};
        uint8_t code[0x245];
        if (readMapped(nullptr,own.function,code,sizeof(code)) ||
            !nativePlatformCacheLocation(code,sizeof(code),own.function,own.bytes)) return 2;
        NativePlatformCacheAPI api{&own, ownRead, ownWrite, ownWritable};
        NativePlatformCacheState state{};
        uint8_t initial[2] = {};
        if (!ownWritable(&own,own.bytes.checked,sizeof(initial)) ||
            ownRead(&own,own.bytes.checked,initial,sizeof(initial))) return 2;
        if (coldStart && (initial[0] || initial[1])) {
            fprintf(stderr,"Platform cache already initialized (%u, %u)\n",initial[0],initial[1]);
            return 2;
        }
        OwnServiceName route;
        bool sharedRoute=coldStart && [endpoint isEqual:ELANSensorServiceName];
        if (sharedRoute) {
            route.slot=location.slot; route.original=location.original; route.size=4096; route.page=route.slot&~4095ULL;
            ReaderMap memory{route};
            auto result=NativeSettingsRoute::apply(memory,base);
            if (result!=NativeSettingsRoute::Result::Routed) {
                fprintf(stderr,"Startup route outcome %u\n",static_cast<unsigned>(result));
                return 3;
            }
            state={own.bytes,{initial[0],initial[1]},true};
        } else {
            if (!route.replace(argv[1],location)) return 3;
            if (nativePlatformEnable(api,own.function,state,coldStart) || memcmp(state.original,initial,sizeof(initial))) {
                nativePlatformRestore(api,state);
                route.restore();
                return 3;
            }
        }
        NSMutableDictionary *report = [NSMutableDictionary new];
        report[@"framework_loaded_prior_to_route"] = @(loadedAtEntry);
        report[@"shared_kernel_route_algorithm"] = @(sharedRoute);
        report[@"cold_start"] = @(coldStart);
        report[@"initial_platform_cache"] = @[@(initial[0]), @(initial[1])];
        report[@"private_endpoint_storage_read_only"] = @YES;
        BOOL ok = NO;
        @try {
            void *framework = dlopen(frameworkPath, RTLD_LAZY | RTLD_LOCAL);
            if (!framework || reinterpret_cast<uint64_t>(dlsym(framework,"isTouchIDPlatformWithFailure")) != own.function) return 2;
            NSArray *devices = [NSClassFromString(@"BKDeviceManager") availableDevices];
            NSError *error = nil;
            id device = devices.count == 1 ? [NSClassFromString(@"BKDevice") deviceWithDescriptor:devices[0] error:&error] : nil;
            report[@"device_class"] = device ? NSStringFromClass([device class]) : @"";
            NSArray *items = device && !error ? [device connectedAccessoriesWithError:&error] : nil;
            id item = items.count == 1 ? items[0] : nil;
            report[@"accessory_class"] = item ? NSStringFromClass([item class]) : @"";
            id serverAccessory = [item valueForKey:@"serverAccessory"];
            BOOL hardware = [item isKindOfClass:NSClassFromString(@"BKAccessory")] &&
                [[item valueForKey:@"name"] isEqual:@"ELAN 0c1a"] &&
                [[[serverAccessory valueForKey:@"uuid"] UUIDString] isEqual:@"0D62A891-28A1-4818-A321-04F3000C1A01"];
            report[@"hardware_accessory"] = @(hardware);
            id enroll = hardware && !error ? [device createEnrollOperationWithError:&error] : nil;
            report[@"enrollment_operation_class"] = enroll ? NSStringFromClass([enroll class]) : @"";
            report[@"error_domain"] = error.domain ?: @"";
            report[@"error_code"] = @(error.code);
            ok = hardware && !error && [device isKindOfClass:NSClassFromString(@"BKDeviceTouchID")] &&
                [enroll isKindOfClass:NSClassFromString(@"BKEnrollTouchIDOperation")];
            if (ok && checkDenial) ok = checkUnprivilegedStart(enroll, device, report);
        } @finally {
            int restored = nativePlatformRestore(api, state);
            BOOL nameRestored = route.restore();
            report[@"service_name_and_page_restored"] = @(nameRestored);
            uint8_t after[2] = {};
            BOOL cacheRestored = !restored && !ownRead(&own,own.bytes.checked,after,sizeof(after)) &&
                                 !memcmp(after,initial,sizeof(initial));
            report[@"original_cache_before_stock_query"] = @(cacheRestored);
            report[@"endpoint_storage_deallocated"] = @(route.replacement == 0);
            BOOL clean = cacheRestored && nameRestored && [ELANSystemTouchIDPlatform() isEqual:@NO] &&
                         [ELANSystemDeviceCount() isEqual:@0];
            report[@"probe_platform_restored"] = @(clean);
            ok &= clean && nameRestored;
        }
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:nil];
        fwrite(data.bytes, 1, data.length, stdout); putchar('\n');
        return ok ? 0 : 1;
    }
}
