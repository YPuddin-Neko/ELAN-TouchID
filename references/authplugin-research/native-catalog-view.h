#pragma once
#import "../../elan-fingerprint-macos/src/ElanFingerprintCatalog.h"

static id nativeIdentityForRecord(ElanFingerprintRecord *record, unsigned user) {
    if (!record) return nil;
    id identity = [NSClassFromString(@"BiometricKitIdentity") new];
    [identity setValue:record.uuid forKey:@"uuid"]; [identity setValue:@1 forKey:@"type"];
    [identity setValue:@(user) forKey:@"userID"]; [identity setValue:record.name forKey:@"name"];
    [identity setValue:record.created forKey:@"creationTime"];
    return identity;
}
static NSArray *nativeCatalogIdentities(ElanFingerprintCatalog *catalog, NSDictionary *query) {
    if (!catalog || (query && ![query isKindOfClass:NSDictionary.class])) return @[];
    id user = query[@"BKFilterUserID"];
    if (user && (![user isKindOfClass:NSNumber.class] || ![user isEqual:@(catalog.user)])) return @[];
    NSMutableArray *identities = [NSMutableArray array];
    for (ElanFingerprintRecord *record in catalog.records) {
        id identity = nativeIdentityForRecord(record, catalog.user);
        if (identity) [identities addObject:identity];
    }
    return identities;
}
static NSData *nativeCatalogIdentityBytes(ElanFingerprintCatalog *catalog) {
    NSMutableData *bytes = [NSMutableData dataWithCapacity:catalog.records.count * 16];
    for (ElanFingerprintRecord *record in catalog.records) {
        uuid_t uuid; [record.uuid getUUIDBytes:uuid];
        [bytes appendBytes:uuid length:sizeof(uuid)];
    }
    return bytes;
}
