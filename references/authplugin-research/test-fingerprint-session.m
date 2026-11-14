#import "../../elan-fingerprint-macos/src/ElanFingerprintSession.h"
#include "fingerprint-catalog-fixtures.h"

#define REQUIRE(condition) do { if (!(condition)) { fprintf(stderr, "SESSION_FAIL line=%d expression=%s\n", __LINE__, #condition); return 1; } } while (0)

static int sessionTests(void) {
    __block NSData *saved = nil;
    __block OSStatus writeStatus = 0;
    __block unsigned writes = 0, publishes = 0, failPublishAt = 0;
    __block ElanFingerprintCatalog *published = nil;
    ElanFingerprintRepository *repo = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64
        reader:^OSStatus(NSData **data) { *data = saved; return saved ? 0 : errSecItemNotFound; }
        writer:^OSStatus(NSData *data, BOOL create) {
            if (writeStatus) return writeStatus;
            if (create && saved) return errSecDuplicateItem;
            if (!create && !saved) return errSecItemNotFound;
            writes++; saved = data; return 0;
        }];
    NSData *templateData = fixtureTemplate(3, 0x0c1a, 144, 64, 8);
    NSUUID *uuid = NSUUID.UUID;
    NSError *error = nil;
    REQUIRE([repo importLegacy:templateData uuid:uuid name:@"Initial" databaseState:[NSMutableData dataWithLength:32] error:&error]);
    ElanCatalogPublisher publisher = ^int(ElanFingerprintCatalog *catalog) {
        publishes++; published = catalog;
        return publishes == failPublishAt ? -70 : 0;
    };
    ElanFingerprintSession *session = [[ElanFingerprintSession alloc] initWithRepository:repo publisher:publisher error:&error];
    REQUIRE(session);
    ElanFingerprintCatalog *first = repo.current;
    ElanFingerprintCatalog *renamed = [first renamingUUID:uuid name:@"Renamed" error:&error];
    REQUIRE([session commit:renamed replacing:first error:&error]);
    REQUIRE(session.matcher.catalog == renamed && repo.current == renamed && published == renamed && writes == 2 && publishes == 1);
    REQUIRE([renamed.databaseState isEqual:first.databaseState] && !session.invalidated);
    REQUIRE(![session commit:first replacing:first error:&error] && publishes == 1 && writes == 2 && !session.invalidated);
    ElanFingerprintCatalog *removed = [renamed removingUUID:uuid error:&error];
    NSData *before = saved;
    writeStatus = errSecInteractionNotAllowed;
    REQUIRE(![session commit:removed replacing:renamed error:&error] && error.code == writeStatus);
    REQUIRE(publishes == 3 && published == renamed && repo.current == renamed && session.matcher.catalog == renamed);
    REQUIRE([saved isEqual:before] && writes == 2 && !session.invalidated);
    writeStatus = 0;
    REQUIRE([session commit:removed replacing:renamed error:&error] && publishes == 4 && writes == 3);
    REQUIRE(repo.current.records.count == 0 && session.matcher.catalog.records.count == 0 && published.records.count == 0);
    REQUIRE(!session.matcher.background);
    puts("SESSION rename=1 stale_commit_rejected=1 failed_write_rolls_back_kernel=1 retry_delete_all=1");

    ElanFingerprintCatalog *added = [removed addingTemplate:templateData uuid:NSUUID.UUID name:@"Another" error:&error];
    failPublishAt = publishes + 1;
    REQUIRE(![session commit:added replacing:removed error:&error] && error.code == -70 && session.invalidated);
    REQUIRE(repo.current == removed && session.matcher.catalog == removed && writes == 3);
    unsigned lastPublish = publishes;
    REQUIRE(![session commit:added replacing:removed error:&error] && publishes == lastPublish && writes == 3);
    session = [[ElanFingerprintSession alloc] initWithRepository:repo publisher:publisher error:&error];
    writeStatus = errSecAuthFailed;
    failPublishAt = publishes + 2;
    REQUIRE(![session commit:added replacing:removed error:&error] && session.invalidated && error.code == -70);
    REQUIRE([error.userInfo[NSUnderlyingErrorKey] code] == writeStatus && repo.current == removed && writes == 3);
    REQUIRE(session.matcher.catalog == removed);
    puts("SESSION uncertain_publish_stops_session=1 rollback_failure_stops_session=1 persisted_catalog_preserved=1");
    return 0;
}
int main(void) {
    @autoreleasepool {
        int result = sessionTests();
        printf("SESSION_DONE status=%d real_keychain_accessed=0 kernel_connected=0 sensor_opened=0\n", result);
        return result;
    }
}
