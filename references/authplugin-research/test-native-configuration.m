#include "native-protected-configuration.h"
#include "fingerprint-catalog-fixtures.h"

#define CHECK_CONFIG(x) do { if (!(x)) { fprintf(stderr, "CONFIG_TEST_FAIL line=%d\n", __LINE__); return 1; } } while (0)

static int configurationModelTests(void) {
    __block NSData *saved = nil;
    __block OSStatus writeStatus = 0;
    __block unsigned writes = 0, authorized = 0, published = 0;
    ElanCatalogReader reader = ^OSStatus(NSData **data) { *data = saved; return saved ? 0 : errSecItemNotFound; };
    ElanCatalogWriter writer = ^OSStatus(NSData *data, BOOL create) {
        if (writeStatus) return writeStatus;
        saved = data; writes++; return 0;
    };
    ElanFingerprintRepository *repo = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64 reader:reader writer:writer];
    CHECK_CONFIG([repo importLegacy:fixtureTemplate(3, 0x0c1a, 144, 64, 24) uuid:NSUUID.UUID name:@"Fixture"
                    databaseState:[NSMutableData dataWithLength:32] error:NULL]);
    ElanFingerprintCatalog *original = repo.current;
    ElanFingerprintSession *session = [[ElanFingerprintSession alloc] initWithRepository:repo
        publisher:^int(ElanFingerprintCatalog *catalog) { published++; return 0; } error:NULL];
    CHECK_CONFIG(session && nativeIdentificationEnabled(session.matcher));
    NSData *context = [NSData dataWithBytes:"fixture-context!" length:16];
    int (^authorize)(NSData *) = ^int(NSData *value) { authorized++; return [value isEqual:context] ? 0 : 1; };
    NSDictionary *disabled = @{@"BKUserCfgTouchIDIdentificationEnabled": @NO};
    unsigned before = writes;
    CHECK_CONFIG(nativeCommitUserConfiguration(session, disabled, [NSData data], authorize) == EACCES);
    CHECK_CONFIG(nativeCommitUserConfiguration(session, disabled, [NSMutableData dataWithLength:16], authorize) == EACCES);
    CHECK_CONFIG(writes == before && authorized == 1 && repo.current == original);
    for (NSString *key in @[@"BKUserCfgTouchIDUnlockEnabled", @"BKUserCfgTouchIDLoginEnabled", @"BKUserCfgTouchIDApplePayEnabled", @"BKUserCfgUnknownEnabled"])
        CHECK_CONFIG(nativeCommitUserConfiguration(session, @{key: @YES}, context, authorize) == ENOTSUP);
    CHECK_CONFIG(nativeCommitUserConfiguration(session, @{@"BKUserCfgTouchIDIdentificationEnabled": @"yes"}, context, authorize) == EINVAL);
    CHECK_CONFIG(nativeCommitUserConfiguration(session, @{@"BKUserCfgTouchIDIdentificationEnabled": @2}, context, authorize) == EINVAL);
    CHECK_CONFIG(writes == before && authorized == 1);
    CHECK_CONFIG(!nativeCommitUserConfiguration(session, disabled, context, authorize));
    CHECK_CONFIG(!nativeIdentificationEnabled(session.matcher) && !repo.current.identificationEnabled);
    CHECK_CONFIG([repo.current.databaseState isEqual:original.databaseState] && [repo.current.records isEqual:original.records]);
    ElanFingerprintRepository *reloaded = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64 reader:reader writer:writer];
    CHECK_CONFIG([reloaded load:NULL] && !reloaded.current.identificationEnabled);
    CHECK_CONFIG(![reloaded.current renamingUUID:original.records[0].uuid name:@"Renamed" error:NULL].identificationEnabled);
    NSData *disabledBytes = saved;
    unsigned beforeFailure = published;
    writeStatus = errSecInteractionNotAllowed;
    CHECK_CONFIG(nativeCommitUserConfiguration(session, @{@"BKUserCfgTouchIDIdentificationEnabled": @YES}, context, authorize) == EIO);
    CHECK_CONFIG(!session.invalidated && !nativeIdentificationEnabled(session.matcher) && [saved isEqual:disabledBytes]);
    CHECK_CONFIG(published == beforeFailure + 2);
    writeStatus = 0;
    CHECK_CONFIG(!nativeCommitUserConfiguration(session, @{@"BKUserCfgTouchIDIdentificationEnabled": @YES}, context, authorize));
    CHECK_CONFIG(nativeIdentificationEnabled(session.matcher) && [repo.current.databaseState isEqual:original.databaseState]);
    NSMutableDictionary *legacy = [[NSPropertyListSerialization propertyListWithData:saved options:NSPropertyListMutableContainers format:NULL error:NULL] mutableCopy];
    legacy[@"schema"] = @1; [legacy removeObjectForKey:@"identification_enabled"];
    NSData *(^encode)(void) = ^NSData * { return [NSPropertyListSerialization dataWithPropertyList:legacy format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL]; };
    CHECK_CONFIG([ElanFingerprintCatalog decode:encode() user:501 pid:0x0c1a width:144 height:64 error:NULL].identificationEnabled);
    legacy[@"schema"] = @2;
    CHECK_CONFIG(![ElanFingerprintCatalog decode:encode() user:501 pid:0x0c1a width:144 height:64 error:NULL]);
    legacy[@"identification_enabled"] = @1;
    CHECK_CONFIG(![ElanFingerprintCatalog decode:encode() user:501 pid:0x0c1a width:144 height:64 error:NULL]);
    legacy[@"identification_enabled"] = @NO;
    CHECK_CONFIG(![ElanFingerprintCatalog decode:encode() user:501 pid:0x0c1a width:144 height:64 error:NULL].identificationEnabled);
    puts("CONFIG_MODEL password_context_required=1 unsupported_changes_rejected=1 persisted_disable_blocks_matching=1 identity_state_preserved=1 failed_write_restored=1 legacy_default_enabled=1 schema2_invalid_rejected=1");
    return 0;
}

#ifndef NATIVE_CONFIGURATION_NO_MAIN
int main(void) { @autoreleasepool { return configurationModelTests(); } }
#endif
