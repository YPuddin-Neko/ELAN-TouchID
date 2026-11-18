#pragma once
#import "ElanFingerprintMatcher.h"

NS_ASSUME_NONNULL_BEGIN
typedef int (^ElanCatalogPublisher)(ElanFingerprintCatalog *catalog);

@interface ElanFingerprintSession : NSObject
@property(nonatomic, readonly) ElanFingerprintMatcher *matcher;
@property(nonatomic, readonly) BOOL invalidated;
// A throwing publisher/store may have changed external state. No retry or rollback is inferred.
@property(nonatomic, readonly) BOOL commitOutcomeUnknown;
- (nullable instancetype)initWithRepository:(ElanFingerprintRepository *)repository
                                 publisher:(ElanCatalogPublisher)publisher error:(NSError **)error;
// Caller holds the sensor operation reservation until this method returns.
- (BOOL)commit:(ElanFingerprintCatalog *)candidate replacing:(ElanFingerprintCatalog *)previous error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
