#import "ElanFingerprintEnrollment.h"
#import "ElanTemplateFormat.h"

@interface ElanFingerprintEnrollment () {
    ElanpressFeatures *_samples[ElanTemplateMaximumSamples];
}
@property(nonatomic) ElanFingerprintMatcher *matcher;
@property(nonatomic) NSMutableData *background;
@property(nonatomic, readwrite) NSUInteger sampleCount;
@property(nonatomic, readwrite) BOOL ended;
@end

static void enrollmentWipe(void *data, size_t length) {
    volatile unsigned char *bytes = data;
    while (length--) *bytes++ = 0;
}
static void enrollmentInvalid(NSError **error) {
    if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:ElanCatalogInvalid userInfo:nil];
}
static BOOL enrollmentFeaturesValid(const ElanpressFeatures *features) {
    if (!features || !features->kp || features->n < ELANPRESS_MATCH_MIN_PAIRS || features->n > ELANPRESS_MAX_KEYPOINTS) return NO;
    for (unsigned i = 0; i < features->n; i++) {
        ElanpressKeypoint point = features->kp[i];
        if (!isfinite(point.x) || !isfinite(point.y) || !isfinite(point.angle) || !isfinite(point.scale)) return NO;
    }
    return YES;
}

@implementation ElanFingerprintEnrollment
- (instancetype)initWithMatcher:(ElanFingerprintMatcher *)matcher background:(NSData *)background
                    targetCount:(NSUInteger)count error:(NSError **)error {
    if (!(self = [super init])) return nil;
    ElanFingerprintCatalog *catalog = matcher.catalog;
    if (!catalog || catalog.records.count >= ElanCatalogMaximumIdentities ||
        count < ElanTemplateMinimumSamples || count > ElanTemplateMaximumSamples ||
        ![background isKindOfClass:NSData.class] || background.length != (size_t)catalog.width * catalog.height * sizeof(uint16_t)) {
        enrollmentInvalid(error); return nil;
    }
    _catalog = catalog; _matcher = matcher; _background = [background mutableCopy]; _targetCount = count;
    return self;
}
- (BOOL)ready { return !self.ended && self.sampleCount == self.targetCount; }
- (ElanEnrollmentSampleResult)appendFeatures:(const ElanpressFeatures *)features score:(unsigned *)score {
    *score = 0;
    if (self.ended || self.ready || !enrollmentFeaturesValid(features)) return ElanEnrollmentSampleInvalid;
    [self.matcher bestRecordForFeatures:features score:score];
    if (*score >= ELANPRESS_MATCH_MIN_PAIRS) return ElanEnrollmentSampleAlreadyEnrolled;
    *score = 0;
    for (NSUInteger i = 0; i < self.sampleCount; i++) {
        unsigned value = elanpress_match_features(features, _samples[i]);
        if (value > *score) *score = value;
    }
    if (self.sampleCount && *score < ELANPRESS_MATCH_MIN_PAIRS) return ElanEnrollmentSampleMismatch;
    ElanpressFeatures *sample = calloc(1, sizeof(*sample));
    if (!sample) return ElanEnrollmentSampleInvalid;
    sample->n = features->n;
    sample->kp = malloc(sample->n * sizeof(*sample->kp));
    if (!sample->kp) { free(sample); return ElanEnrollmentSampleInvalid; }
    memcpy(sample->kp, features->kp, sample->n * sizeof(*sample->kp));
    _samples[_sampleCount++] = sample;
    return ElanEnrollmentSampleAccepted;
}
- (ElanFingerprintRecord *)commitWithSession:(ElanFingerprintSession *)session uuid:(NSUUID *)uuid
                                      name:(NSString *)name error:(NSError **)error {
    if (!self.ready || session.invalidated || session.matcher.catalog != self.catalog) { enrollmentInvalid(error); return nil; }
    NSMutableArray *items = [NSMutableArray array];
    for (NSUInteger i = 0; i < self.sampleCount; i++)
        [items addObject:[NSData dataWithBytes:_samples[i]->kp length:_samples[i]->n * sizeof(*_samples[i]->kp)]];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:@{@"schema": @3, @"pid": @(self.catalog.pid),
        @"width": @(self.catalog.width), @"height": @(self.catalog.height), @"prints": items, @"background": self.background}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    ElanFingerprintCatalog *next = data ? [self.catalog addingTemplate:data uuid:uuid name:name error:error] : nil;
    if (!next || ![session commit:next replacing:self.catalog error:error]) return nil;
    ElanFingerprintRecord *record = [next recordForUUID:uuid];
    [self cancel];
    return record;
}
- (void)cancel {
    for (NSUInteger i = 0; i < self.sampleCount; i++) {
        enrollmentWipe(_samples[i]->kp, _samples[i]->n * sizeof(*_samples[i]->kp));
        elanpress_features_free(_samples[i]); _samples[i] = NULL;
    }
    self.sampleCount = 0;
    enrollmentWipe(self.background.mutableBytes, self.background.length);
    self.background = nil;
    self.ended = YES;
}
- (void)dealloc { [self cancel]; }
@end

@interface ElanFingerprintSupplement ()
@property(nonatomic) ElanFingerprintMatcher *matcher;
@property(nonatomic, readwrite) ElanFingerprintRecord *record;
@property(nonatomic, readwrite) NSUInteger sampleCount;
@end
@implementation ElanFingerprintSupplement
- (instancetype)initWithMatcher:(ElanFingerprintMatcher *)matcher uuid:(NSUUID *)uuid error:(NSError **)error {
    if (!(self = [super init])) return nil;
    ElanFingerprintCatalog *catalog = matcher.catalog;
    ElanFingerprintRecord *record = [catalog recordForUUID:uuid];
    NSDictionary *decoded = record ? ElanDecodeTemplate(record.templateData, catalog.pid, catalog.width, catalog.height) : nil;
    if (!decoded) { enrollmentInvalid(error); return nil; }
    _matcher = matcher; _record = record; _sampleCount = [decoded[@"prints"] count];
    return self;
}
- (ElanEnrollmentSampleResult)appendFeatures:(const ElanpressFeatures *)features
                                  toSession:(ElanFingerprintSession *)session score:(unsigned *)score error:(NSError **)error {
    *score = 0;
    ElanFingerprintCatalog *previous = self.matcher.catalog;
    if (!enrollmentFeaturesValid(features) || !session || session.invalidated || session.matcher.catalog != previous) {
        enrollmentInvalid(error); return ElanEnrollmentSampleInvalid;
    }
    if (self.sampleCount >= ElanTemplateMaximumSamples) {
        if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:ElanCatalogFull userInfo:nil];
        return ElanEnrollmentSampleInvalid;
    }
    ElanFingerprintRecord *matched = [self.matcher bestRecordForFeatures:features score:score];
    if (*score < ELANPRESS_MATCH_MIN_PAIRS || ![matched.uuid isEqual:self.record.uuid]) return ElanEnrollmentSampleMismatch;
    NSMutableDictionary *decoded = [ElanDecodeTemplate(self.record.templateData, previous.pid, previous.width, previous.height) mutableCopy];
    NSMutableArray *prints = [decoded[@"prints"] mutableCopy];
    NSMutableData *sample = [NSMutableData dataWithBytes:features->kp length:features->n * sizeof(*features->kp)];
    [prints addObject:sample]; decoded[@"prints"] = prints; decoded[@"schema"] = @3; decoded[@"pid"] = @(previous.pid);
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:decoded format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    enrollmentWipe(sample.mutableBytes, sample.length);
    ElanFingerprintCatalog *next = data ? [previous replacingTemplate:data uuid:self.record.uuid error:error] : nil;
    if (!next || ![session commit:next replacing:previous error:error]) return ElanEnrollmentSampleInvalid;
    self.matcher = session.matcher; self.record = [next recordForUUID:self.record.uuid]; self.sampleCount++;
    return ElanEnrollmentSampleAccepted;
}
@end
