#pragma once
#include "ElanNativeProbe.h"
#include "NativeEnrollmentAuthorization.h"

union NativeProviderInput {
    NativeProviderRequest provider;
    NativePlatformProcessRequest platform;
    NativeProviderCatalogRequest catalog;
    NativeEnrollmentRequest enrollment;
    NativeSettingsProcessRequest settings;
};
union NativeProviderOutput {
    NativeProviderReport provider;
    NativePlatformProcessReport platform;
    NativeProviderCatalogReport catalog;
    NativeEnrollmentReport enrollment;
};

static inline bool nativeProviderIsSelector(uint32_t selector) {
    return selector >= ElanProviderBegin && selector <= ElanProviderSettingsRestore;
}
static inline size_t nativeProviderInputSize(uint32_t selector) {
    switch (selector) {
        case ElanProviderBegin: case ElanProviderMatch: return sizeof(NativeProviderRequest);
        case ElanProviderPlatformEnable: return sizeof(NativePlatformProcessRequest);
        case ElanProviderCatalogBegin: case ElanProviderCatalogReplace: return sizeof(NativeProviderCatalogRequest);
        case ElanProviderAuthorizeEnrollment: return sizeof(NativeEnrollmentRequest);
        case ElanProviderSettingsEnable: return sizeof(NativeSettingsProcessRequest);
        default: return 0;
    }
}
static inline size_t nativeProviderOutputSize(uint32_t selector) {
    switch (selector) {
        case ElanProviderBegin: case ElanProviderMatch: case ElanProviderEnd: return sizeof(NativeProviderReport);
        case ElanProviderPlatformEnable: case ElanProviderPlatformRestore: return sizeof(NativePlatformProcessReport);
        case ElanProviderSettingsEnable: case ElanProviderSettingsRestore: return sizeof(NativePlatformProcessReport);
        case ElanProviderCatalogBegin: case ElanProviderCatalogReplace: return sizeof(NativeProviderCatalogReport);
        case ElanProviderAuthorizeEnrollment: return sizeof(NativeEnrollmentReport);
        default: return 0;
    }
}
