#import "ElanFingerprintSession.h"

@interface ElanFingerprintSession ()
@property(nonatomic) ElanFingerprintRepository *repository;
@property(nonatomic, copy) ElanCatalogPublisher publisher;
@property(nonatomic, readwrite) ElanFingerprintMatcher *matcher;
@property(nonatomic, readwrite) BOOL invalidated;
@end

@implementation ElanFingerprintSession
- (instancetype)initWithRepository:(ElanFingerprintRepository *)repository publisher:(ElanCatalogPublisher)publisher error:(NSError **)error {
    if (!(self = [super init])) return nil;
    _matcher = [[ElanFingerprintMatcher alloc] initWithCatalog:repository.current error:error];
    if (!_matcher) return nil;
    _repository = repository; _publisher = [publisher copy];
    return self;
}
- (BOOL)commit:(ElanFingerprintCatalog *)candidate replacing:(ElanFingerprintCatalog *)previous error:(NSError **)error {
    @synchronized (self) {
        if (self.invalidated || !previous || self.matcher.catalog != previous || self.repository.current != previous ||
            !candidate || candidate.user != previous.user || candidate.pid != previous.pid ||
            candidate.width != previous.width || candidate.height != previous.height) {
            if (error) *error = [NSError errorWithDomain:ElanFingerprintCatalogErrorDomain code:ElanCatalogInvalid userInfo:nil];
            return NO;
        }
        ElanFingerprintMatcher *prepared = [[ElanFingerprintMatcher alloc] initWithCatalog:candidate error:error];
        if (!prepared) return NO;
        int status = self.publisher(candidate);
        if (status) {
            self.invalidated = YES;
            if (error) *error = [NSError errorWithDomain:@"io.github.hackintosh-tools.elan.provider" code:status userInfo:nil];
            return NO;
        }
        NSError *writeError = nil;
        if (![self.repository commit:candidate replacing:previous error:&writeError]) {
            int restored = self.publisher(previous);
            self.invalidated = restored != 0;
            if (error) *error = restored ? [NSError errorWithDomain:@"io.github.hackintosh-tools.elan.provider" code:restored
                userInfo:writeError ? @{NSUnderlyingErrorKey: writeError} : nil] : writeError;
            return NO;
        }
        self.matcher = prepared;
        return YES;
    }
}
@end
