#pragma once
#import <Foundation/Foundation.h>
#include <math.h>
#include "elanpress-match.h"

enum { ElanTemplateMinimumSamples = 8, ElanTemplateMaximumSamples = 24 };

static inline NSDictionary *ElanDecodeTemplate(NSData *data, unsigned pid, unsigned width, unsigned height) {
    if (![data isKindOfClass:NSData.class] || !width || !height) return nil;
    id record = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil];
    if (![record isKindOfClass:NSDictionary.class]) return nil;
    BOOL expanded = [record[@"schema"] isEqual:@3];
    BOOL current = (expanded || [record[@"schema"] isEqual:@2]) && [record[@"pid"] isEqual:@(pid)];
    BOOL legacy = [record[@"schema"] isEqual:@1] && pid == 0x0c6e;
    if ((!current && !legacy) || ![record[@"width"] isEqual:@(width)] || ![record[@"height"] isEqual:@(height)]) return nil;
    id items = record[@"prints"], background = record[@"background"];
    size_t frameBytes = (size_t)width * height * sizeof(uint16_t);
    if (![items isKindOfClass:NSArray.class] || [items count] < ElanTemplateMinimumSamples ||
        [items count] > ElanTemplateMaximumSamples || (!expanded && [items count] != ElanTemplateMinimumSamples) ||
        ![background isKindOfClass:NSData.class] || [background length] != frameBytes) return nil;
    for (id item in items) {
        if (![item isKindOfClass:NSData.class] || [item length] % sizeof(ElanpressKeypoint) ||
            [item length] < ELANPRESS_MATCH_MIN_PAIRS * sizeof(ElanpressKeypoint) ||
            [item length] > ELANPRESS_MAX_KEYPOINTS * sizeof(ElanpressKeypoint)) return nil;
        const unsigned char *bytes = [item bytes];
        for (NSUInteger offset = 0; offset < [item length]; offset += sizeof(ElanpressKeypoint)) {
            ElanpressKeypoint point;
            memcpy(&point, bytes + offset, sizeof(point));
            if (!isfinite(point.x) || !isfinite(point.y) || !isfinite(point.angle) || !isfinite(point.scale)) return nil;
        }
    }
    return record;
}
