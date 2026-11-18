#pragma once
#import "ElanFingerprintCatalog.h"
#include "elanpress-match.h"

NS_ASSUME_NONNULL_BEGIN
@interface ElanFingerprintMatcher : NSObject
@property(nonatomic, readonly) ElanFingerprintCatalog *catalog;
@property(nonatomic, readonly, nullable) NSData *background;
- (nullable instancetype)initWithCatalog:(ElanFingerprintCatalog *)catalog error:(NSError **)error;
// Returns the best candidate even below threshold. The caller applies the existing match threshold.
- (nullable ElanFingerprintRecord *)bestRecordForFeatures:(const ElanpressFeatures *)features score:(unsigned *)score;
@end
NS_ASSUME_NONNULL_END
