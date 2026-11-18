#pragma once
#import "ElanFingerprintSession.h"

NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(unsigned, ElanEnrollmentSampleResult) {
    ElanEnrollmentSampleAccepted,
    ElanEnrollmentSampleMismatch,
    ElanEnrollmentSampleAlreadyEnrolled,
    ElanEnrollmentSampleInvalid,
};

// The sensor queue owns the draft until it is committed or cancelled.
@interface ElanFingerprintEnrollment : NSObject
@property(nonatomic, readonly) ElanFingerprintCatalog *catalog;
@property(nonatomic, readonly) NSUInteger sampleCount;
@property(nonatomic, readonly) NSUInteger targetCount;
@property(nonatomic, readonly) BOOL ready;
@property(nonatomic, readonly) BOOL ended;
- (nullable instancetype)initWithMatcher:(ElanFingerprintMatcher *)matcher
                             background:(NSData *)background targetCount:(NSUInteger)count error:(NSError **)error;
- (ElanEnrollmentSampleResult)appendFeatures:(const ElanpressFeatures *)features score:(unsigned *)score;
- (nullable ElanFingerprintRecord *)commitWithSession:(ElanFingerprintSession *)session
                                               uuid:(NSUUID *)uuid name:(NSString *)name error:(NSError **)error;
- (void)cancel;
@end

@interface ElanFingerprintSupplement : NSObject
@property(nonatomic, readonly) ElanFingerprintRecord *record;
@property(nonatomic, readonly) NSUInteger sampleCount;
- (nullable instancetype)initWithMatcher:(ElanFingerprintMatcher *)matcher uuid:(NSUUID *)uuid error:(NSError **)error;
// Accepted means the sample was matched, published, and saved.
- (ElanEnrollmentSampleResult)appendFeatures:(const ElanpressFeatures *)features
                                  toSession:(ElanFingerprintSession *)session score:(unsigned *)score error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
