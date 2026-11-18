#import "../../src/ElanFingerprintMatcher.h"
#import "../../src/ElanTemplateFormat.h"

#define REQUIRE(condition) do { if (!(condition)) { fprintf(stderr, "MULTIFINGER_FAIL line=%d expression=%s\n", __LINE__, #condition); return 1; } } while (0)

static ElanpressFeatures *imageFeatures(uint32_t seed) {
    unsigned char image[144 * 64];
    for (size_t i = 0; i < sizeof(image); i++) { seed = seed * 1664525u + 1013904223u; image[i] = seed >> 24; }
    return elanpress_image_features(image, 144, 64);
}
static NSData *templateForFeatures(ElanpressFeatures *features, unsigned count, uint16_t level) {
    NSMutableData *background = [NSMutableData dataWithLength:144 * 64 * sizeof(uint16_t)];
    uint16_t *pixels = background.mutableBytes;
    for (unsigned i = 0; i < 144 * 64; i++) pixels[i] = level;
    NSData *sample = [NSData dataWithBytes:features->kp length:features->n * sizeof(*features->kp)];
    NSMutableArray *prints = [NSMutableArray array];
    for (unsigned i = 0; i < count; i++) [prints addObject:sample];
    return [NSPropertyListSerialization dataWithPropertyList:@{@"schema": @3, @"pid": @0x0c1a,
        @"width": @144, @"height": @64, @"prints": prints, @"background": background}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
}
static int matchTests(ElanpressFeatures *features[4]) {
    NSError *error = nil;
    ElanFingerprintCatalog *catalog = [ElanFingerprintCatalog emptyForUser:501 pid:0x0c1a width:144 height:64 error:&error];
    NSMutableArray<NSUUID *> *uuids = [NSMutableArray array];
    NSMutableArray<NSData *> *templates = [NSMutableArray array];
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(features[i] && features[i]->n >= ELANPRESS_MATCH_MIN_PAIRS);
        NSUUID *uuid = NSUUID.UUID; [uuids addObject:uuid];
        NSData *data = templateForFeatures(features[i], 8 + 8 * i, 1000 + 1000 * i); [templates addObject:data];
        catalog = [catalog addingTemplate:data uuid:uuid name:[NSString stringWithFormat:@"Finger %u", i + 1] error:&error];
        REQUIRE(catalog);
    }
    ElanFingerprintMatcher *matcher = [[ElanFingerprintMatcher alloc] initWithCatalog:catalog error:&error];
    REQUIRE(matcher && matcher.background.length == 144 * 64 * 2);
    NSData *background = [matcher.background copy];
    REQUIRE(((const uint16_t *)background.bytes)[0] == 1000);
    for (unsigned i = 0; i < 3; i++) {
        unsigned score = 0;
        ElanFingerprintRecord *record = [matcher bestRecordForFeatures:features[i] score:&score];
        REQUIRE([record.uuid isEqual:uuids[i]] && score >= ELANPRESS_MATCH_MIN_PAIRS);
        printf("MULTIFINGER identity=%u points=%u score=%u correct_identity=1\n", i + 1, features[i]->n, score);
    }
    unsigned score = 999;
    REQUIRE(features[3]);
    [matcher bestRecordForFeatures:features[3] score:&score];
    REQUIRE(score < ELANPRESS_MATCH_MIN_PAIRS);
    printf("MULTIFINGER unrelated_score=%u threshold=%u\n", score, ELANPRESS_MATCH_MIN_PAIRS);
    ElanpressFeatures blank = {};
    REQUIRE(![matcher bestRecordForFeatures:&blank score:&score] && !score);
    REQUIRE([matcher.background isEqual:background]);
    for (unsigned i = 0; i < 3; i++) REQUIRE([catalog.records[i].templateData isEqual:templates[i]]);
    ElanFingerprintCatalog *removed = [catalog removingUUID:uuids[1] error:&error];
    ElanFingerprintMatcher *afterRemoval = [[ElanFingerprintMatcher alloc] initWithCatalog:removed error:&error];
    ElanFingerprintRecord *record = [afterRemoval bestRecordForFeatures:features[1] score:&score];
    REQUIRE(![record.uuid isEqual:uuids[1]] && score < ELANPRESS_MATCH_MIN_PAIRS);
    REQUIRE([[[matcher bestRecordForFeatures:features[1] score:&score] uuid] isEqual:uuids[1]]);
    ElanFingerprintCatalog *renamed = [removed renamingUUID:uuids[0] name:@"Renamed" error:&error];
    ElanFingerprintMatcher *afterRename = [[ElanFingerprintMatcher alloc] initWithCatalog:renamed error:&error];
    record = [afterRename bestRecordForFeatures:features[0] score:&score];
    REQUIRE([record.uuid isEqual:uuids[0]] && [record.name isEqual:@"Renamed"] && score >= ELANPRESS_MATCH_MIN_PAIRS);
    for (ElanFingerprintRecord *item in [renamed.records copy]) renamed = [renamed removingUUID:item.uuid error:&error];
    ElanFingerprintMatcher *empty = [[ElanFingerprintMatcher alloc] initWithCatalog:renamed error:&error];
    REQUIRE(empty && !empty.background && ![empty bestRecordForFeatures:features[0] score:&score] && !score);
    puts("MULTIFINGER removed_identity_rejected=1 snapshot_preserved=1 rename_preserves_identity=1 background_unchanged=1 empty_catalog=1");
    return 0;
}
int main(void) {
    @autoreleasepool {
        ElanpressFeatures *features[4];
        for (unsigned i = 0; i < 4; i++) features[i] = imageFeatures(13 + 986 * i);
        int result = matchTests(features);
        for (unsigned i = 0; i < 4; i++) elanpress_features_free(features[i]);
        printf("MULTIFINGER_DONE status=%d real_fingerprint_samples=0 sensor_opened=0\n", result);
        return result;
    }
}
