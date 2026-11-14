#import "../../elan-fingerprint-macos/src/ElanFingerprintCatalog.h"
#import "../../elan-fingerprint-macos/src/ElanTemplateFormat.h"

#define REQUIRE(condition) do { if (!(condition)) { fprintf(stderr, "CATALOG_FAIL line=%d expression=%s\n", __LINE__, #condition); return 1; } } while (0)

#include "fingerprint-catalog-fixtures.h"

static int catalogTests(void) {
    NSData *legacy = fixtureTemplate(3, 0x0c1a, 144, 64, 24);
    NSData *legacyOriginal = [legacy copy];
    NSData *legacyState = [@"legacy-biometry-state-32-bytes!!" dataUsingEncoding:NSUTF8StringEncoding];
    REQUIRE(legacyState.length == 32);
    NSData *shortTemplate = fixtureTemplate(2, 0x0c1a, 144, 64, 8);
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:@"6AF9A0D7-3E65-42E8-8D65-36F4AA1598F7"];
    __block NSData *saved = nil;
    __block OSStatus readFailure = 0, writeFailure = 0;
    __block unsigned writes = 0;
    ElanCatalogReader reader = ^OSStatus(NSData **data) {
        if (readFailure) return readFailure;
        if (!saved) return errSecItemNotFound;
        *data = saved; return errSecSuccess;
    };
    ElanCatalogWriter writer = ^OSStatus(NSData *data, BOOL create) {
        if (writeFailure) return writeFailure;
        if (create && saved) return errSecDuplicateItem;
        if (!create && !saved) return errSecItemNotFound;
        saved = [data copy]; writes++; return errSecSuccess;
    };
    ElanFingerprintRepository *(^repository)(void) = ^{
        return [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64 reader:reader writer:writer];
    };
    ElanFingerprintRepository *repo = repository();
    NSError *error = nil;
    REQUIRE(![repo load:&error] && error.code == errSecItemNotFound && !repo.current && !writes);
    writeFailure = errSecInteractionNotAllowed;
    REQUIRE(![repo importLegacy:legacy uuid:uuid name:@"原有指纹" databaseState:legacyState error:&error] && !repo.current && !saved && !writes);
    writeFailure = 0;
    REQUIRE([repo importLegacy:legacy uuid:uuid name:@"原有指纹" databaseState:legacyState error:&error]);
    REQUIRE([legacy isEqual:legacyOriginal] && [repo.current.records[0].templateData isEqual:legacy]);
    REQUIRE([repo.current.records[0].uuid isEqual:uuid]);
    ElanFingerprintCatalog *first = repo.current;
    REQUIRE([first.databaseState isEqual:legacyState]);
    ElanFingerprintRepository *reloaded = repository();
    REQUIRE([reloaded load:&error] && [reloaded.current.databaseState isEqual:first.databaseState]);
    REQUIRE([reloaded.current.records[0].uuid isEqual:uuid] && [reloaded.current.records[0].created isEqual:first.records[0].created]);
    puts("CATALOG migration_preserves_template_uuid_date_state=1 failed_migration_leaves_legacy=1 reload=1");

    NSMutableString *newName = [@"左手食指" mutableCopy];
    ElanFingerprintCatalog *renamed = [first renamingUUID:uuid name:newName error:&error];
    [newName appendString:@"changed"];
    REQUIRE([renamed.records[0].name isEqual:@"左手食指"] && [renamed.databaseState isEqual:first.databaseState]);
    NSData *before = saved;
    writeFailure = errSecInteractionNotAllowed;
    REQUIRE(![repo commit:renamed replacing:first error:&error] && repo.current == first && [saved isEqual:before]);
    writeFailure = 0;
    REQUIRE([repo commit:renamed replacing:first error:&error]);
    REQUIRE(![repo commit:first replacing:first error:&error] && repo.current == renamed);
    REQUIRE([repo.current.records[0].templateData isEqual:legacy] && [repo.current.records[0].uuid isEqual:uuid]);
    puts("CATALOG rename_preserves_identity_and_state=1 failed_write_keeps_current=1 stale_commit_rejected=1");

    NSUUID *secondUUID = NSUUID.UUID;
    ElanFingerprintCatalog *added = [renamed addingTemplate:shortTemplate uuid:secondUUID name:@"右手食指" error:&error];
    REQUIRE(added.records.count == 2 && ![added.databaseState isEqual:renamed.databaseState]);
    REQUIRE([repo commit:added replacing:renamed error:&error]);
    ElanFingerprintCatalog *extended = [added replacingTemplate:legacy uuid:secondUUID error:&error];
    REQUIRE([extended.databaseState isEqual:added.databaseState] && [extended recordForUUID:secondUUID].templateData.length == legacy.length);
    REQUIRE([[extended recordForUUID:secondUUID].created isEqual:[added recordForUUID:secondUUID].created]);
    REQUIRE([repo commit:extended replacing:added error:&error]);
    ElanFingerprintCatalog *removed = [extended removingUUID:uuid error:&error];
    REQUIRE(removed.records.count == 1 && ![removed.databaseState isEqual:extended.databaseState] && [removed recordForUUID:secondUUID]);
    REQUIRE([repo commit:removed replacing:extended error:&error]);
    ElanFingerprintCatalog *empty = [removed removingUUID:secondUUID error:&error];
    REQUIRE([repo commit:empty replacing:removed error:&error]);
    REQUIRE(![repo importLegacy:legacy uuid:uuid name:@"旧数据" databaseState:legacyState error:&error] && error.code == errSecDuplicateItem && repo.current == empty);
    ElanFingerprintRepository *emptyReloaded = repository();
    REQUIRE([emptyReloaded load:&error] && emptyReloaded.current.records.count == 0);
    REQUIRE([emptyReloaded.current.databaseState isEqual:empty.databaseState]);
    puts("CATALOG add_remove_change_state=1 extend_preserves_identity=1 empty_persists_without_legacy_resurrection=1");

    unsigned writesBefore = writes;
    readFailure = errSecInteractionNotAllowed;
    REQUIRE(![emptyReloaded load:&error] && error.code == errSecInteractionNotAllowed && !emptyReloaded.current && writes == writesBefore);
    readFailure = 0;
    NSData *validSaved = saved;
    saved = [@"corrupt" dataUsingEncoding:NSUTF8StringEncoding];
    REQUIRE(![emptyReloaded load:&error] && [error.domain isEqual:ElanFingerprintCatalogErrorDomain] && writes == writesBefore);
    REQUIRE(![emptyReloaded importLegacy:legacy uuid:uuid name:@"旧数据" databaseState:legacyState error:&error] && error.code == errSecDuplicateItem && writes == writesBefore);
    saved = validSaved;
    REQUIRE([emptyReloaded load:&error]);
    puts("CATALOG locked_or_corrupt_store_never_overwritten=1");

    ElanFingerprintCatalog *capacity = first;
    for (unsigned i = 1; i < ElanCatalogMaximumIdentities; i++) capacity = [capacity addingTemplate:legacy uuid:NSUUID.UUID name:@"Finger" error:&error];
    REQUIRE(capacity.records.count == ElanCatalogMaximumIdentities);
    ElanFingerprintCatalog *cleared = [capacity removingAll:&error];
    REQUIRE(cleared && !cleared.records.count && ![cleared.databaseState isEqual:capacity.databaseState]);
    REQUIRE([cleared removingAll:&error] == cleared);
    REQUIRE(![capacity addingTemplate:legacy uuid:NSUUID.UUID name:@"Full" error:&error] && error.code == ElanCatalogFull);
    REQUIRE(![first addingTemplate:legacy uuid:uuid name:@"Duplicate" error:&error]);
    REQUIRE(![first addingTemplate:legacy uuid:[[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"] name:@"Zero" error:&error]);
    REQUIRE(![first renamingUUID:uuid name:@"  " error:&error]);
    REQUIRE(![first removingUUID:NSUUID.UUID error:&error]);
    REQUIRE(![first replacingTemplate:fixtureTemplate(3, 0x0c1a, 144, 64, 25) uuid:uuid error:&error]);
    REQUIRE(![ElanFingerprintCatalog decode:[first encoded:&error] user:502 pid:0x0c1a width:144 height:64 error:&error]);
    NSMutableDictionary *encoded = [[NSPropertyListSerialization propertyListWithData:[first encoded:&error] options:NSPropertyListMutableContainers format:NULL error:nil] mutableCopy];
    encoded[@"records"] = @[encoded[@"records"][0], encoded[@"records"][0]];
    NSData *duplicate = [NSPropertyListSerialization dataWithPropertyList:encoded format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    REQUIRE(![ElanFingerprintCatalog decode:duplicate user:501 pid:0x0c1a width:144 height:64 error:&error]);
    REQUIRE(ElanDecodeTemplate(fixtureTemplate(1, 0x0c6e, 150, 52, 8), 0x0c6e, 150, 52));
    REQUIRE(!ElanDecodeTemplate(fixtureTemplate(1, 0x0c6e, 150, 52, 8), 0x0c1a, 144, 64));
    NSMutableDictionary *badTemplate = [[NSPropertyListSerialization propertyListWithData:shortTemplate options:NSPropertyListMutableContainers format:NULL error:nil] mutableCopy];
    NSMutableArray *badPrints = [badTemplate[@"prints"] mutableCopy];
    NSMutableData *badPoint = [badPrints[0] mutableCopy];
    ElanpressKeypoint point; memcpy(&point, badPoint.bytes, sizeof(point)); point.scale = NAN;
    memcpy(badPoint.mutableBytes, &point, sizeof(point)); badPrints[0] = badPoint; badTemplate[@"prints"] = badPrints;
    NSData *invalid = [NSPropertyListSerialization dataWithPropertyList:badTemplate format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    REQUIRE(!ElanDecodeTemplate(invalid, 0x0c1a, 144, 64));
    puts("CATALOG limits_user_device_duplicates_and_template_validation=1");
    return 0;
}

static int migrationTests(void) {
    __block NSData *stored = nil;
    __block NSData *legacy = fixtureTemplate(3, 0x0c1a, 144, 64, 24);
    NSData *original = [legacy copy];
    __block OSStatus nativeError = 0, legacyError = 0, writeError = 0;
    __block unsigned legacyReads = 0, writes = 0;
    ElanCatalogReader nativeReader = ^OSStatus(NSData **data) {
        if (nativeError) return nativeError;
        if (!stored) return errSecItemNotFound;
        *data = stored; return 0;
    };
    ElanCatalogReader legacyReader = ^OSStatus(NSData **data) {
        legacyReads++;
        if (legacyError) return legacyError;
        *data = legacy; return 0;
    };
    ElanCatalogWriter writer = ^OSStatus(NSData *data, BOOL create) {
        REQUIRE(create);
        if (writeError) return writeError;
        if (stored) return errSecDuplicateItem;
        stored = data; writes++; return 0;
    };
    ElanFingerprintRepository *repo = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64 reader:nativeReader writer:writer];
    NSError *error = nil;
    nativeError = errSecInteractionNotAllowed;
    REQUIRE(![repo loadOrMigrateLegacy:legacyReader error:&error] && error.code == nativeError && !legacyReads && !writes);
    nativeError = 0; stored = [@"invalid" dataUsingEncoding:NSUTF8StringEncoding];
    REQUIRE(![repo loadOrMigrateLegacy:legacyReader error:&error] && [error.domain isEqual:ElanFingerprintCatalogErrorDomain] && !legacyReads && !writes);
    stored = nil; legacyError = errSecAuthFailed;
    REQUIRE(![repo loadOrMigrateLegacy:legacyReader error:&error] && error.code == legacyError && legacyReads == 1 && !writes);
    legacyError = 0; legacy = [@"bad legacy" dataUsingEncoding:NSUTF8StringEncoding];
    REQUIRE(![repo loadOrMigrateLegacy:legacyReader error:&error] && error.code == ElanCatalogInvalid && !writes && !stored);
    legacy = original; writeError = errSecInteractionNotAllowed;
    REQUIRE(![repo loadOrMigrateLegacy:legacyReader error:&error] && error.code == writeError && !repo.current && !stored && !writes);
    writeError = 0;
    REQUIRE([repo loadOrMigrateLegacy:legacyReader error:&error] && writes == 1 && repo.current.records.count == 1);
    REQUIRE([repo.current.records[0].templateData isEqual:original] && [legacy isEqual:original]);
    ElanFingerprintCatalog *migrated = repo.current;
    REQUIRE(migrated.databaseState.length == 32);
    uuid_t migratedUUID; [migrated.records[0].uuid getUUIDBytes:migratedUUID];
    REQUIRE(!memcmp(migratedUUID, migrated.databaseState.bytes, sizeof(migratedUUID)));
    unsigned readsBefore = legacyReads;
    legacyError = errSecAuthFailed;
    REQUIRE([repo loadOrMigrateLegacy:legacyReader error:&error] && legacyReads == readsBefore && writes == 1);
    REQUIRE([repo.current.databaseState isEqual:migrated.databaseState] && [repo.current.records[0].uuid isEqual:migrated.records[0].uuid]);
    stored = nil; legacyError = errSecItemNotFound;
    REQUIRE([repo loadOrMigrateLegacy:legacyReader error:&error] && repo.current.records.count == 0 && writes == 2);
    readsBefore = legacyReads; legacyError = 0;
    REQUIRE([repo loadOrMigrateLegacy:legacyReader error:&error] && repo.current.records.count == 0 && legacyReads == readsBefore && writes == 2);
    puts("CATALOG automatic_migration_missing_only=1 denied_or_corrupt_not_replaced=1 existing_empty_never_reimports=1 migration_failure_keeps_legacy=1");
    return 0;
}

int main(void) {
    @autoreleasepool {
        int result = catalogTests() | migrationTests();
        printf("CATALOG_DONE status=%d real_keychain_accessed=0 sensor_opened=0 system_service_changed=0\n", result);
        return result;
    }
}
