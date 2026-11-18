#import "ElanFingerprintMatcher.h"
#import "ElanTemplateFormat.h"

@interface ElanFingerprintSamples : NSObject {
    ElanpressFeatures *_samples[ElanTemplateMaximumSamples];
    unsigned _count;
}
@property(nonatomic, readonly) ElanFingerprintRecord *record;
- (instancetype)initWithRecord:(ElanFingerprintRecord *)record decoded:(NSDictionary *)decoded;
- (unsigned)score:(const ElanpressFeatures *)features;
@end
@implementation ElanFingerprintSamples
- (instancetype)initWithRecord:(ElanFingerprintRecord *)record decoded:(NSDictionary *)decoded {
    if ((self = [super init])) {
        _record = record;
        NSArray *items = decoded[@"prints"];
        for (NSData *item in items) {
            ElanpressFeatures *sample = calloc(1, sizeof(*sample));
            if (!sample) return nil;
            _samples[_count++] = sample;
            sample->kp = malloc(item.length);
            if (!sample->kp) return nil;
            sample->n = (guint)(item.length / sizeof(*sample->kp));
            memcpy(sample->kp, item.bytes, item.length);
        }
    }
    return self;
}
- (unsigned)score:(const ElanpressFeatures *)features {
    unsigned best = 0;
    for (unsigned i = 0; i < _count; i++) {
        unsigned value = elanpress_match_features(features, _samples[i]);
        if (value > best) best = value;
    }
    return best;
}
- (void)dealloc {
    for (unsigned i = 0; i < _count; i++) {
        ElanpressFeatures *sample = _samples[i];
        volatile unsigned char *bytes = (unsigned char *)sample->kp;
        for (size_t j = 0; j < sample->n * sizeof(*sample->kp); j++) bytes[j] = 0;
        elanpress_features_free(sample);
    }
}
@end

@interface ElanFingerprintMatcher ()
@property(nonatomic, copy) NSArray<ElanFingerprintSamples *> *samples;
@end
@implementation ElanFingerprintMatcher
- (instancetype)initWithCatalog:(ElanFingerprintCatalog *)catalog error:(NSError **)error {
    if (!(self = [super init])) return nil;
    if (!catalog || catalog.records.count > ElanCatalogMaximumIdentities) {
        if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:ElanCatalogInvalid userInfo:nil];
        return nil;
    }
    _catalog = catalog;
    NSMutableArray *samples = [NSMutableArray array];
    for (ElanFingerprintRecord *record in catalog.records) {
        NSDictionary *decoded = ElanDecodeTemplate(record.templateData, catalog.pid, catalog.width, catalog.height);
        ElanFingerprintSamples *item = decoded ? [[ElanFingerprintSamples alloc] initWithRecord:record decoded:decoded] : nil;
        if (!item) {
            if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:ElanCatalogInvalid userInfo:nil];
            return nil;
        }
        [samples addObject:item];
        if (!_background) _background = [decoded[@"background"] copy];
    }
    self.samples = samples;
    return self;
}
- (ElanFingerprintRecord *)bestRecordForFeatures:(const ElanpressFeatures *)features score:(unsigned *)score {
    *score = 0;
    if (!features || !features->kp || !features->n) return nil;
    ElanFingerprintRecord *best = nil;
    for (ElanFingerprintSamples *samples in self.samples) {
        unsigned value = [samples score:features];
        if (!best || value > *score) { best = samples.record; *score = value; }
    }
    return best;
}
@end
