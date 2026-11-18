#import "ElanFingerprintCatalog.h"
#import "ElanTemplateFormat.h"
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

NSString *const ElanFingerprintCatalogErrorDomain = @"io.github.hackintosh-tools.elan.catalog";
static BOOL catalogError(NSError **error, NSInteger code) {
    if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:code userInfo:nil];
    return NO;
}
static BOOL storageError(NSError **error, OSStatus status) {
    if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    return NO;
}
static BOOL validName(id name) {
    return [name isKindOfClass:NSString.class] && [name length] <= 128 &&
        [[name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] length] > 0;
}
static BOOL validDevice(unsigned user, unsigned pid, unsigned width, unsigned height) {
    return user && ((pid == 0x0c1a && width == 144 && height == 64) || (pid == 0x0c6e && width == 150 && height == 52));
}
static BOOL validUUID(NSUUID *uuid) {
    if (![uuid isKindOfClass:NSUUID.class]) return NO;
    uuid_t bytes; [uuid getUUIDBytes:bytes]; unsigned present = 0;
    for (unsigned i = 0; i < sizeof(bytes); i++) present |= bytes[i];
    return present != 0;
}
static NSData *newDatabaseState(NSError **error) {
    unsigned char bytes[32];
    OSStatus status = SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes);
    if (status) { storageError(error, status); return nil; }
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

@interface ElanFingerprintRecord ()
- (instancetype)initWithUUID:(NSUUID *)uuid name:(NSString *)name created:(NSDate *)created data:(NSData *)data;
@end
@implementation ElanFingerprintRecord
- (instancetype)initWithUUID:(NSUUID *)uuid name:(NSString *)name created:(NSDate *)created data:(NSData *)data {
    if ((self = [super init])) { _uuid = [uuid copy]; _name = [name copy]; _created = [created copy]; _templateData = [data copy]; }
    return self;
}
@end

@interface ElanFingerprintCatalog ()
@property(nonatomic, readwrite) unsigned user, pid, width, height;
@property(nonatomic, readwrite) BOOL identificationEnabled;
@property(nonatomic, readwrite, copy) NSData *databaseState;
@property(nonatomic, readwrite, copy) NSArray<ElanFingerprintRecord *> *records;
@end
@implementation ElanFingerprintCatalog
+ (instancetype)emptyForUser:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height error:(NSError **)error {
    if (!validDevice(user, pid, width, height)) {
        catalogError(error, ElanCatalogInvalid); return nil;
    }
    NSData *state = newDatabaseState(error);
    if (!state) return nil;
    ElanFingerprintCatalog *catalog = [self new];
    catalog.user = user; catalog.pid = pid; catalog.width = width; catalog.height = height;
    catalog.databaseState = state; catalog.records = @[]; catalog.identificationEnabled = YES;
    return catalog;
}
+ (instancetype)decode:(NSData *)data user:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height error:(NSError **)error {
    id value = [data isKindOfClass:NSData.class] ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil] : nil;
    if (!validDevice(user, pid, width, height) || ![value isKindOfClass:NSDictionary.class] ||
        (![value[@"schema"] isEqual:@1] && ![value[@"schema"] isEqual:@2]) ||
        ![value[@"user"] isEqual:@(user)] || ![value[@"pid"] isEqual:@(pid)] ||
        ![value[@"width"] isEqual:@(width)] || ![value[@"height"] isEqual:@(height)] ||
        ![value[@"state"] isKindOfClass:NSData.class] || [value[@"state"] length] != 32 ||
        ![value[@"records"] isKindOfClass:NSArray.class] || [value[@"records"] count] > ElanCatalogMaximumIdentities) {
        catalogError(error, ElanCatalogInvalid); return nil;
    }
    if ([value[@"schema"] isEqual:@2] &&
        (![value[@"identification_enabled"] isKindOfClass:NSNumber.class] ||
         CFGetTypeID((__bridge CFTypeRef)value[@"identification_enabled"]) != CFBooleanGetTypeID())) {
        catalogError(error, ElanCatalogInvalid); return nil;
    }
    NSMutableArray *records = [NSMutableArray array];
    NSMutableSet *uuids = [NSMutableSet set];
    for (id item in value[@"records"]) {
        if (![item isKindOfClass:NSDictionary.class] || ![item[@"uuid"] isKindOfClass:NSString.class] ||
            !validName(item[@"name"]) || ![item[@"created"] isKindOfClass:NSDate.class] ||
            !ElanDecodeTemplate(item[@"template"], pid, width, height)) {
            catalogError(error, ElanCatalogInvalid); return nil;
        }
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:item[@"uuid"]];
        if (!validUUID(uuid) || [uuids containsObject:uuid]) { catalogError(error, ElanCatalogInvalid); return nil; }
        [uuids addObject:uuid];
        [records addObject:[[ElanFingerprintRecord alloc] initWithUUID:uuid name:item[@"name"] created:item[@"created"] data:item[@"template"]]];
    }
    ElanFingerprintCatalog *catalog = [self new];
    catalog.user = user; catalog.pid = pid; catalog.width = width; catalog.height = height;
    catalog.databaseState = value[@"state"]; catalog.records = records;
    catalog.identificationEnabled = [value[@"schema"] isEqual:@1] || [value[@"identification_enabled"] boolValue];
    return catalog;
}
- (NSData *)encoded:(NSError **)error {
    NSMutableArray *records = [NSMutableArray array];
    for (ElanFingerprintRecord *record in self.records)
        [records addObject:@{@"uuid": record.uuid.UUIDString, @"name": record.name, @"created": record.created, @"template": record.templateData}];
    return [NSPropertyListSerialization dataWithPropertyList:@{@"schema": @2, @"user": @(self.user), @"pid": @(self.pid),
        @"identification_enabled": @(self.identificationEnabled),
        @"width": @(self.width), @"height": @(self.height), @"state": self.databaseState, @"records": records}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
}
- (ElanFingerprintRecord *)recordForUUID:(NSUUID *)uuid {
    for (ElanFingerprintRecord *record in self.records) if ([record.uuid isEqual:uuid]) return record;
    return nil;
}
- (instancetype)withRecords:(NSArray *)records membershipChanged:(BOOL)changed error:(NSError **)error {
    NSData *state = changed ? newDatabaseState(error) : self.databaseState;
    if (!state) return nil;
    ElanFingerprintCatalog *catalog = [ElanFingerprintCatalog new];
    catalog.user = self.user; catalog.pid = self.pid; catalog.width = self.width; catalog.height = self.height;
    catalog.records = records; catalog.databaseState = state;
    catalog.identificationEnabled = self.identificationEnabled;
    return catalog;
}
- (instancetype)withIdentificationEnabled:(BOOL)enabled {
    ElanFingerprintCatalog *catalog = [self withRecords:self.records membershipChanged:NO error:NULL];
    catalog.identificationEnabled = enabled;
    return catalog;
}
- (instancetype)addingTemplate:(NSData *)data uuid:(NSUUID *)uuid name:(NSString *)name error:(NSError **)error {
    if (!validUUID(uuid) || !validName(name) || [self recordForUUID:uuid] ||
        !ElanDecodeTemplate(data, self.pid, self.width, self.height)) { catalogError(error, ElanCatalogInvalid); return nil; }
    if (self.records.count == ElanCatalogMaximumIdentities) { catalogError(error, ElanCatalogFull); return nil; }
    ElanFingerprintRecord *record = [[ElanFingerprintRecord alloc] initWithUUID:uuid name:name created:NSDate.date data:data];
    return [self withRecords:[self.records arrayByAddingObject:record] membershipChanged:YES error:error];
}
- (instancetype)renamingUUID:(NSUUID *)uuid name:(NSString *)name error:(NSError **)error {
    ElanFingerprintRecord *old = [self recordForUUID:uuid];
    if (!old) { catalogError(error, ElanCatalogMissing); return nil; }
    if (!validName(name)) { catalogError(error, ElanCatalogInvalid); return nil; }
    NSMutableArray *records = [self.records mutableCopy];
    records[[records indexOfObjectIdenticalTo:old]] = [[ElanFingerprintRecord alloc] initWithUUID:old.uuid name:name created:old.created data:old.templateData];
    return [self withRecords:records membershipChanged:NO error:error];
}
- (instancetype)removingUUID:(NSUUID *)uuid error:(NSError **)error {
    ElanFingerprintRecord *old = [self recordForUUID:uuid];
    if (!old) { catalogError(error, ElanCatalogMissing); return nil; }
    NSMutableArray *records = [self.records mutableCopy]; [records removeObjectIdenticalTo:old];
    return [self withRecords:records membershipChanged:YES error:error];
}
- (instancetype)replacingTemplate:(NSData *)data uuid:(NSUUID *)uuid error:(NSError **)error {
    ElanFingerprintRecord *old = [self recordForUUID:uuid];
    if (!old) { catalogError(error, ElanCatalogMissing); return nil; }
    if (!ElanDecodeTemplate(data, self.pid, self.width, self.height)) { catalogError(error, ElanCatalogInvalid); return nil; }
    NSMutableArray *records = [self.records mutableCopy];
    records[[records indexOfObjectIdenticalTo:old]] = [[ElanFingerprintRecord alloc] initWithUUID:old.uuid name:old.name created:old.created data:data];
    return [self withRecords:records membershipChanged:NO error:error];
}
- (instancetype)removingAll:(NSError **)error {
    return self.records.count ? [self withRecords:@[] membershipChanged:YES error:error] : self;
}
@end

@interface ElanFingerprintRepository ()
@property(nonatomic, readwrite) ElanFingerprintCatalog *current;
@property(nonatomic) unsigned user, pid, width, height;
@property(nonatomic, copy) ElanCatalogReader reader;
@property(nonatomic, copy) ElanCatalogWriter writer;
@end

static NSDictionary *keychainQuery(NSString *account) {
    return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"io.github.hackintosh-tools.elan-unlock", (__bridge id)kSecAttrAccount: account};
}
static ElanCatalogReader keychainReader(unsigned user, NSString *account, BOOL interactive) {
    NSDictionary *query = keychainQuery(account);
    return ^OSStatus(NSData **data) {
        *data = nil;
        if (getuid() != user) return errSecAuthFailed;
        NSMutableDictionary *read = [query mutableCopy];
        read[(__bridge id)kSecReturnData] = @YES; read[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        if (!interactive) read[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
        CFTypeRef value = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)read, &value);
        id result = CFBridgingRelease(value);
        if (status == errSecSuccess && ![result isKindOfClass:NSData.class]) return errSecDecode;
        if (!status) *data = result;
        return status;
    };
}
static ElanCatalogReader fileReader(NSURL *fileURL, unsigned user) {
    NSURL *target = [fileURL copy];
    return ^OSStatus(NSData **data) {
        *data = nil;
        if (getuid() != user || ![target isKindOfClass:NSURL.class] || !target.isFileURL || !target.path.length)
            return errSecAuthFailed;
        const char *path = target.fileSystemRepresentation;
        if (!path) return errSecParam;
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT) return errSecItemNotFound;
            return (errno == ELOOP || errno == EACCES || errno == EPERM) ? errSecAuthFailed : errSecIO;
        }
        struct stat st = {};
        if (fstat(fd, &st) != 0) { close(fd); return errSecIO; }
        if (st.st_uid != user || !S_ISREG(st.st_mode)) { close(fd); return errSecAuthFailed; }
        if (st.st_size <= 0 || st.st_size > 4 * 1024 * 1024) { close(fd); return errSecDecode; }
        NSMutableData *buffer = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
        if (!buffer) { close(fd); return errSecAllocate; }
        uint8_t *bytes = (uint8_t *)buffer.mutableBytes;
        size_t remaining = (size_t)st.st_size;
        while (remaining > 0) {
            ssize_t got = read(fd, bytes, remaining);
            if (got < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return errSecIO;
            }
            if (got == 0) { close(fd); return errSecDecode; }
            bytes += (size_t)got;
            remaining -= (size_t)got;
        }
        close(fd);
        *data = buffer;
        return errSecSuccess;
    };
}
static ElanCatalogWriter fileWriter(NSURL *fileURL, unsigned user) {
    NSURL *target = [fileURL copy];
    return ^OSStatus(NSData *data, BOOL create) {
        (void)create;
        if (getuid() != user || ![target isKindOfClass:NSURL.class] || !target.isFileURL ||
            !target.path.length || ![data isKindOfClass:NSData.class]) return errSecAuthFailed;
        NSURL *dirURL = [target URLByDeletingLastPathComponent];
        const char *dirPath = dirURL.fileSystemRepresentation;
        const char *destPath = target.fileSystemRepresentation;
        if (!dirPath || !destPath) return errSecParam;
        (void)[[NSFileManager defaultManager] createDirectoryAtURL:dirURL
            withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:NULL];
        if (mkdir(dirPath, 0700) != 0 && errno != EEXIST) return errSecIO;
        struct stat dirStat = {};
        if (lstat(dirPath, &dirStat) != 0 || !S_ISDIR(dirStat.st_mode) || dirStat.st_uid != user)
            return errSecAuthFailed;
        if ((dirStat.st_mode & 0077) != 0) (void)chmod(dirPath, 0700);
        struct stat destStat = {};
        if (lstat(destPath, &destStat) == 0 && (!S_ISREG(destStat.st_mode) || destStat.st_uid != user))
            return errSecAuthFailed;
        NSString *pattern = [dirURL.path stringByAppendingPathComponent:@".native-catalog.XXXXXX"];
        NSMutableData *tmplData = [[pattern dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        if (!tmplData) return errSecParam;
        char nul = 0;
        [tmplData appendBytes:&nul length:1];
        char *tmpl = (char *)tmplData.mutableBytes;
        int fd = mkstemp(tmpl);
        if (fd < 0) return errSecIO;
        if (fchmod(fd, 0600) != 0) { close(fd); unlink(tmpl); return errSecIO; }
        const uint8_t *bytes = (const uint8_t *)data.bytes;
        size_t remaining = data.length;
        while (remaining > 0) {
            ssize_t put = write(fd, bytes, remaining);
            if (put < 0) {
                if (errno == EINTR) continue;
                close(fd); unlink(tmpl);
                return errSecIO;
            }
            bytes += (size_t)put;
            remaining -= (size_t)put;
        }
        if (fsync(fd) != 0) { close(fd); unlink(tmpl); return errSecIO; }
        if (close(fd) != 0) { unlink(tmpl); return errSecIO; }
        if (rename(tmpl, destPath) != 0) { unlink(tmpl); return errSecIO; }
        return errSecSuccess;
    };
}
@implementation ElanFingerprintRepository
- (instancetype)initWithUser:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height reader:(ElanCatalogReader)reader writer:(ElanCatalogWriter)writer {
    if ((self = [super init])) { _user = user; _pid = pid; _width = width; _height = height; _reader = [reader copy]; _writer = [writer copy]; }
    return self;
}
- (instancetype)initWithFileURL:(NSURL *)fileURL user:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height {
    return [self initWithUser:user pid:pid width:width height:height reader:fileReader(fileURL, user) writer:fileWriter(fileURL, user)];
}
- (instancetype)initWithUserKeychain:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height interactive:(BOOL)interactive {
    NSDictionary *query = keychainQuery(@"native-fingerprints-v1");
    ElanCatalogReader reader = keychainReader(user, @"native-fingerprints-v1", interactive);
    ElanCatalogWriter writer = ^OSStatus(NSData *data, BOOL create) {
        if (getuid() != user) return errSecAuthFailed;
        NSMutableDictionary *write = [query mutableCopy];
        if (!interactive) write[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
        if (create) { write[(__bridge id)kSecValueData] = data; return SecItemAdd((__bridge CFDictionaryRef)write, NULL); }
        return SecItemUpdate((__bridge CFDictionaryRef)write, (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData: data});
    };
    return [self initWithUser:user pid:pid width:width height:height reader:reader writer:writer];
}
- (BOOL)load:(NSError **)error {
    @synchronized (self) {
        NSData *data = nil; OSStatus status = self.reader(&data);
        self.current = nil;
        if (status) return storageError(error, status);
        self.current = [ElanFingerprintCatalog decode:data user:self.user pid:self.pid width:self.width height:self.height error:error];
        return self.current != nil;
    }
}
- (BOOL)loadOrMigrateLegacy:(ElanCatalogReader)legacyReader error:(NSError **)error {
    return [self loadWithLegacyReader:legacyReader persistMigration:YES error:error];
}
- (BOOL)loadSnapshotFromUserKeychain:(NSError **)error {
    return [self loadWithLegacyReader:keychainReader(self.user, @"fingerprints-v1", NO) persistMigration:NO error:error];
}
- (BOOL)useMigration:(ElanFingerprintCatalog *)catalog persist:(BOOL)persist error:(NSError **)error {
    if (!catalog) return NO;
    if (persist) return [self writeNew:catalog error:error];
    self.current = catalog;
    return YES;
}
- (BOOL)loadWithLegacyReader:(ElanCatalogReader)legacyReader persistMigration:(BOOL)persist error:(NSError **)error {
    @synchronized (self) {
        NSError *failure = nil;
        if ([self load:&failure]) return YES;
        if (![failure.domain isEqual:NSOSStatusErrorDomain] || failure.code != errSecItemNotFound) {
            if (error) *error = failure;
            return NO;
        }
        NSData *data = nil;
        OSStatus status = legacyReader(&data);
        if (status == errSecItemNotFound) {
            ElanFingerprintCatalog *empty = [ElanFingerprintCatalog emptyForUser:self.user pid:self.pid
                width:self.width height:self.height error:error];
            return [self useMigration:empty persist:persist error:error];
        }
        if (status) return storageError(error, status);
        if (!ElanDecodeTemplate(data, self.pid, self.width, self.height) || data.length > UINT32_MAX)
            return catalogError(error, ElanCatalogInvalid);
        // Preserve the identity and database state used by the original single-finger provider.
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:digest];
        NSData *state = [NSData dataWithBytes:digest length:sizeof(digest)];
        volatile unsigned char *bytes = digest;
        for (size_t i = 0; i < sizeof(digest); i++) bytes[i] = 0;
        ElanFingerprintCatalog *legacy = [self catalogForTemplate:data uuid:uuid name:@"ELAN" state:state error:error];
        return [self useMigration:legacy persist:persist error:error];
    }
}
- (BOOL)loadOrMigrateLegacyFromUserKeychain:(BOOL)interactive error:(NSError **)error {
    return [self loadOrMigrateLegacy:keychainReader(self.user, @"fingerprints-v1", interactive) error:error];
}
- (BOOL)writeNew:(ElanFingerprintCatalog *)catalog error:(NSError **)error {
    if (!catalog) return NO;
    NSData *data = [catalog encoded:error]; if (!data) return NO;
    OSStatus status = self.writer(data, YES);
    if (status) return storageError(error, status);
    self.current = catalog; return YES;
}
- (ElanFingerprintCatalog *)catalogForTemplate:(NSData *)data uuid:(NSUUID *)uuid name:(NSString *)name
                                        state:(NSData *)state error:(NSError **)error {
    if (![state isKindOfClass:NSData.class] || state.length != 32) {
        catalogError(error, ElanCatalogInvalid);
        return nil;
    }
    ElanFingerprintCatalog *empty = [ElanFingerprintCatalog emptyForUser:self.user pid:self.pid width:self.width height:self.height error:error];
    ElanFingerprintCatalog *migrated = [empty addingTemplate:data uuid:uuid name:name error:error];
    migrated.databaseState = state;
    return migrated;
}
- (BOOL)importLegacy:(NSData *)data uuid:(NSUUID *)uuid name:(NSString *)name databaseState:(NSData *)state error:(NSError **)error {
    @synchronized (self) {
        return [self writeNew:[self catalogForTemplate:data uuid:uuid name:name state:state error:error] error:error];
    }
}
- (BOOL)createEmpty:(NSError **)error {
    @synchronized (self) {
        return [self writeNew:[ElanFingerprintCatalog emptyForUser:self.user pid:self.pid width:self.width height:self.height error:error] error:error];
    }
}
- (BOOL)commit:(ElanFingerprintCatalog *)candidate replacing:(ElanFingerprintCatalog *)previous error:(NSError **)error {
    @synchronized (self) {
        if (!previous || self.current != previous || !candidate || candidate.user != self.user || candidate.pid != self.pid ||
            candidate.width != self.width || candidate.height != self.height) return catalogError(error, ElanCatalogInvalid);
        NSData *data = [candidate encoded:error]; if (!data) return NO;
        OSStatus status = self.writer(data, NO);
        if (status) return storageError(error, status);
        self.current = candidate; return YES;
    }
}
@end
