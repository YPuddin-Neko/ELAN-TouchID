#import "../../src/ElanFingerprintEnrollment.h"
#import "../../src/ElanTemplateFormat.h"
#include "native-enrollment-progress.h"

#define REQUIRE(condition) do { if (!(condition)) { fprintf(stderr, "ENROLLMENT_FAIL line=%d expression=%s\n", __LINE__, #condition); return 1; } } while (0)

static ElanpressFeatures *generatedFeatures(uint32_t seed) {
    unsigned char image[144 * 64];
    for (size_t i = 0; i < sizeof(image); i++) { seed = seed * 1664525u + 1013904223u; image[i] = seed >> 24; }
    return elanpress_image_features(image, 144, 64);
}
static int enrollmentTests(ElanpressFeatures *first, ElanpressFeatures *other) {
    __block NSData *stored = nil;
    __block ElanFingerprintCatalog *published = nil;
    __block OSStatus writeStatus = 0;
    __block unsigned writes = 0;
    ElanFingerprintRepository *repository = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64
        reader:^OSStatus(NSData **data) { *data = stored; return stored ? 0 : errSecItemNotFound; }
        writer:^OSStatus(NSData *data, BOOL create) {
            writes++;
            if (writeStatus) return writeStatus;
            if (create && stored) return errSecDuplicateItem;
            if (!create && !stored) return errSecItemNotFound;
            stored = data; return 0;
        }];
    REQUIRE([repository createEmpty:NULL]);
    ElanFingerprintSession *session = [[ElanFingerprintSession alloc] initWithRepository:repository
        publisher:^int(ElanFingerprintCatalog *catalog) { published = catalog; return 0; } error:NULL];
    REQUIRE(session && first && other && first->n >= ELANPRESS_MATCH_MIN_PAIRS && other->n >= ELANPRESS_MATCH_MIN_PAIRS);
    NSMutableData *background = [NSMutableData dataWithLength:144 * 64 * 2];
    ((uint16_t *)background.mutableBytes)[0] = 1234;
    REQUIRE(![[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:7 error:NULL]);
    REQUIRE(![[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:25 error:NULL]);
    REQUIRE(![[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:NSData.data targetCount:8 error:NULL]);
    ElanFingerprintEnrollment *draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:8 error:NULL];
    REQUIRE(draft && !draft.ready);
    ((uint16_t *)background.mutableBytes)[0] = 0;
    unsigned score = 0;
    ElanpressFeatures invalid = {.n = first->n, .kp = malloc(first->n * sizeof(*first->kp))};
    memcpy(invalid.kp, first->kp, first->n * sizeof(*first->kp)); invalid.kp[0].x = NAN;
    REQUIRE([draft appendFeatures:&invalid score:&score] == ElanEnrollmentSampleInvalid);
    free(invalid.kp);
    REQUIRE([draft appendFeatures:first score:&score] == ElanEnrollmentSampleAccepted);
    REQUIRE([draft appendFeatures:other score:&score] == ElanEnrollmentSampleMismatch && draft.sampleCount == 1);
    REQUIRE(![draft commitWithSession:session uuid:NSUUID.UUID name:@"Incomplete" error:NULL] && writes == 1);
    for (unsigned i = 1; i < 8; i++) REQUIRE([draft appendFeatures:first score:&score] == ElanEnrollmentSampleAccepted);
    REQUIRE(draft.ready && [draft appendFeatures:first score:&score] == ElanEnrollmentSampleInvalid && writes == 1);
    ElanFingerprintCatalog *before = repository.current;
    NSUUID *uuid = NSUUID.UUID;
    writeStatus = errSecInteractionNotAllowed;
    NSError *error = nil;
    REQUIRE(![draft commitWithSession:session uuid:uuid name:@"First" error:&error] && error);
    REQUIRE(repository.current == before && published == before && session.matcher.catalog == before && !session.invalidated && draft.ready);
    writeStatus = 0;
    ElanFingerprintRecord *record = [draft commitWithSession:session uuid:uuid name:@"First" error:NULL];
    REQUIRE(record && [record.uuid isEqual:uuid] && draft.ended && !draft.sampleCount && !draft.ready);
    REQUIRE(repository.current.records.count == 1 && published == repository.current && session.matcher.catalog == published);
    NSDictionary *decoded = ElanDecodeTemplate(record.templateData, 0x0c1a, 144, 64);
    REQUIRE([decoded[@"prints"] count] == 8 && ((const uint16_t *)[decoded[@"background"] bytes])[0] == 1234);
    unsigned afterCommit = writes;
    REQUIRE(![draft commitWithSession:session uuid:uuid name:@"Again" error:NULL] && writes == afterCommit);
    draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:24 error:NULL];
    REQUIRE([draft appendFeatures:first score:&score] == ElanEnrollmentSampleAlreadyEnrolled && !draft.sampleCount);
    REQUIRE([draft appendFeatures:other score:&score] == ElanEnrollmentSampleAccepted);
    [draft cancel]; [draft cancel];
    REQUIRE(draft.ended && !draft.sampleCount && !draft.ready && writes == afterCommit);
    REQUIRE([draft appendFeatures:other score:&score] == ElanEnrollmentSampleInvalid);
    REQUIRE(![draft commitWithSession:session uuid:NSUUID.UUID name:@"Cancelled" error:NULL]);
    puts("ENROLLMENT partial_not_saved=1 mismatch_rejected=1 duplicate_rejected=1 cancellation_discards=1 failed_write_rolled_back=1 retry_saved=1 copied_background=1");
    draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:24 error:NULL];
    unsigned priorProgress = 0;
    for (unsigned i = 0; i < 24; i++) {
        REQUIRE([draft appendFeatures:other score:&score] == ElanEnrollmentSampleAccepted);
        unsigned progress = nativeEnrollmentProgress((unsigned)draft.sampleCount, 24);
        REQUIRE(progress > priorProgress && progress <= 355); priorProgress = progress;
    }
    REQUIRE(priorProgress == 355 && draft.ready);
    ElanFingerprintCatalog *changed = [repository.current renamingUUID:uuid name:@"Renamed" error:NULL];
    REQUIRE([session commit:changed replacing:repository.current error:NULL]);
    unsigned afterRename = writes;
    REQUIRE(![draft commitWithSession:session uuid:NSUUID.UUID name:@"Stale draft" error:NULL] && draft.ready && writes == afterRename);
    [draft cancel];
    draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:session.matcher background:background targetCount:24 error:NULL];
    for (unsigned i = 0; i < 24; i++) REQUIRE([draft appendFeatures:other score:&score] == ElanEnrollmentSampleAccepted);
    record = [draft commitWithSession:session uuid:NSUUID.UUID name:@"Second" error:NULL];
    REQUIRE(record && [ElanDecodeTemplate(record.templateData, 0x0c1a, 144, 64)[@"prints"] count] == 24);
    REQUIRE([[[session.matcher bestRecordForFeatures:other score:&score] uuid] isEqual:record.uuid] && score >= ELANPRESS_MATCH_MIN_PAIRS);
    REQUIRE(repository.current.records.count == 2 && published == repository.current);
    puts("ENROLLMENT full_24_samples=1 catalog_change_rejected=1 new_identity_matches=1 original_identity_preserved=1");
    REQUIRE(nativeEnrollmentProgress(0, 8) == 100 && nativeEnrollmentProgress(1, 8) == 132 &&
            nativeEnrollmentProgress(4, 8) == 228 && nativeEnrollmentProgress(8, 8) == 355 && nativeEnrollmentProgress(9, 8) == 355);
    REQUIRE(![[ElanFingerprintSupplement alloc] initWithMatcher:session.matcher uuid:NSUUID.UUID error:NULL]);
    ElanFingerprintSupplement *supplement = [[ElanFingerprintSupplement alloc] initWithMatcher:session.matcher uuid:uuid error:NULL];
    REQUIRE(supplement && supplement.sampleCount == 8);
    before = repository.current; afterCommit = writes;
    REQUIRE([supplement appendFeatures:other toSession:session score:&score error:NULL] == ElanEnrollmentSampleMismatch);
    REQUIRE(repository.current == before && writes == afterCommit && supplement.sampleCount == 8);
    ElanpressFeatures malformed = {.n = ELANPRESS_MAX_KEYPOINTS + 1, .kp = first->kp};
    REQUIRE([supplement appendFeatures:&malformed toSession:session score:&score error:NULL] == ElanEnrollmentSampleInvalid);
    writeStatus = errSecInteractionNotAllowed;
    REQUIRE([supplement appendFeatures:first toSession:session score:&score error:NULL] == ElanEnrollmentSampleInvalid);
    REQUIRE(repository.current == before && published == before && session.matcher.catalog == before && supplement.sampleCount == 8);
    writeStatus = 0;
    REQUIRE([supplement appendFeatures:first toSession:session score:&score error:NULL] == ElanEnrollmentSampleAccepted);
    REQUIRE(supplement.sampleCount == 9 && [supplement.record.uuid isEqual:uuid] && [supplement.record.name isEqual:@"Renamed"]);
    REQUIRE([supplement.record.created isEqual:[before recordForUUID:uuid].created] && [repository.current.databaseState isEqual:before.databaseState]);
    decoded = ElanDecodeTemplate(supplement.record.templateData, 0x0c1a, 144, 64);
    REQUIRE([decoded[@"prints"] count] == 9 && [decoded[@"prints"] lastObject] &&
        [[decoded[@"prints"] lastObject] isEqual:[NSData dataWithBytes:first->kp length:first->n * sizeof(*first->kp)]]);
    REQUIRE([decoded[@"background"] isEqual:ElanDecodeTemplate([before recordForUUID:uuid].templateData, 0x0c1a, 144, 64)[@"background"]]);
    changed = [repository.current renamingUUID:uuid name:@"Same finger" error:NULL];
    REQUIRE([session commit:changed replacing:repository.current error:NULL]);
    afterCommit = writes;
    REQUIRE([supplement appendFeatures:first toSession:session score:&score error:NULL] == ElanEnrollmentSampleInvalid && writes == afterCommit);
    supplement = [[ElanFingerprintSupplement alloc] initWithMatcher:session.matcher uuid:uuid error:NULL];
    for (unsigned i = 9; i < 24; i++) REQUIRE([supplement appendFeatures:first toSession:session score:&score error:NULL] == ElanEnrollmentSampleAccepted);
    before = repository.current; afterCommit = writes; error = nil;
    REQUIRE([supplement appendFeatures:first toSession:session score:&score error:&error] == ElanEnrollmentSampleInvalid);
    REQUIRE(error.code == ElanCatalogFull && supplement.sampleCount == 24 && repository.current == before && writes == afterCommit);
    REQUIRE([[[session.matcher bestRecordForFeatures:first score:&score] uuid] isEqual:uuid] && score >= ELANPRESS_MATCH_MIN_PAIRS);
    REQUIRE([repository.current recordForUUID:record.uuid].templateData == record.templateData);
    puts("SUPPLEMENT wrong_identity_rejected=1 invalid_rejected=1 write_failure_rolled_back=1 retry_saved=1 identity_state_preserved=1 sample_copied=1 stale_rejected=1 capacity_enforced=1");
    return 0;
}
int main(void) {
    @autoreleasepool {
        ElanpressFeatures *first = generatedFeatures(13), *other = generatedFeatures(999);
        int result = enrollmentTests(first, other);
        elanpress_features_free(first); elanpress_features_free(other);
        printf("ENROLLMENT_DONE status=%d sensor_opened=0 keychain_read=0 memory_storage=1 simulated_kernel=1\n", result);
        return result;
    }
}
