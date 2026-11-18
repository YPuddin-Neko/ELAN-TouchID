#pragma once
#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN
extern NSString *const ElanFingerprintCatalogErrorDomain;
enum { ElanCatalogInvalid = 1, ElanCatalogFull = 2, ElanCatalogMissing = 3 };
enum { ElanCatalogMaximumIdentities = 3 };

@interface ElanFingerprintRecord : NSObject
@property(nonatomic, readonly, copy) NSUUID *uuid;
@property(nonatomic, readonly, copy) NSString *name;
@property(nonatomic, readonly, copy) NSDate *created;
@property(nonatomic, readonly, copy) NSData *templateData;
@end

@interface ElanFingerprintCatalog : NSObject
@property(nonatomic, readonly) unsigned user;
@property(nonatomic, readonly) unsigned pid;
@property(nonatomic, readonly) unsigned width;
@property(nonatomic, readonly) unsigned height;
@property(nonatomic, readonly) BOOL identificationEnabled;
@property(nonatomic, readonly, copy) NSData *databaseState;
@property(nonatomic, readonly, copy) NSArray<ElanFingerprintRecord *> *records;
+ (nullable instancetype)emptyForUser:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height error:(NSError **)error;
+ (nullable instancetype)decode:(NSData *)data user:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height error:(NSError **)error;
- (nullable NSData *)encoded:(NSError **)error;
- (nullable ElanFingerprintRecord *)recordForUUID:(NSUUID *)uuid;
- (nullable instancetype)addingTemplate:(NSData *)data uuid:(NSUUID *)uuid name:(NSString *)name error:(NSError **)error;
- (nullable instancetype)renamingUUID:(NSUUID *)uuid name:(NSString *)name error:(NSError **)error;
- (nullable instancetype)removingUUID:(NSUUID *)uuid error:(NSError **)error;
- (nullable instancetype)removingAll:(NSError **)error;
- (nullable instancetype)replacingTemplate:(NSData *)data uuid:(NSUUID *)uuid error:(NSError **)error;
- (instancetype)withIdentificationEnabled:(BOOL)enabled;
@end

typedef OSStatus (^ElanCatalogReader)(NSData * _Nullable * _Nonnull data);
typedef OSStatus (^ElanCatalogWriter)(NSData *data, BOOL create);

@interface ElanFingerprintRepository : NSObject
@property(nonatomic, readonly, nullable) ElanFingerprintCatalog *current;
- (instancetype)initWithUser:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height
                      reader:(ElanCatalogReader)reader writer:(ElanCatalogWriter)writer;
- (instancetype)initWithFileURL:(NSURL *)fileURL user:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height;
- (instancetype)initWithUserKeychain:(unsigned)user pid:(unsigned)pid width:(unsigned)width height:(unsigned)height interactive:(BOOL)interactive;
- (BOOL)load:(NSError **)error;
- (BOOL)loadWithLegacyReader:(ElanCatalogReader)reader persistMigration:(BOOL)persist error:(NSError **)error;
- (BOOL)loadSnapshotFromUserKeychain:(NSError **)error;
- (BOOL)loadOrMigrateLegacy:(ElanCatalogReader)legacyReader error:(NSError **)error;
- (BOOL)loadOrMigrateLegacyFromUserKeychain:(BOOL)interactive error:(NSError **)error;
// Creates a separate Keychain item; the caller retains the legacy item for rollback.
- (BOOL)importLegacy:(NSData *)data uuid:(NSUUID *)uuid name:(NSString *)name databaseState:(NSData *)state error:(NSError **)error;
- (BOOL)createEmpty:(NSError **)error;
- (BOOL)commit:(ElanFingerprintCatalog *)candidate replacing:(ElanFingerprintCatalog *)previous error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
