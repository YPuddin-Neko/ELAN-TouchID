#pragma once
#import "../../elan-fingerprint-macos/src/ElanTemplateFormat.h"

static NSData *fixtureTemplate(unsigned schema, unsigned pid, unsigned width, unsigned height, unsigned samples) {
    ElanpressKeypoint points[ELANPRESS_MATCH_MIN_PAIRS] = {};
    for (unsigned i = 0; i < ELANPRESS_MATCH_MIN_PAIRS; i++) { points[i].x = i; points[i].y = i + 1; points[i].scale = 1; }
    NSData *sample = [NSData dataWithBytes:points length:sizeof(points)];
    NSMutableArray *prints = [NSMutableArray array];
    for (unsigned i = 0; i < samples; i++) [prints addObject:sample];
    return [NSPropertyListSerialization dataWithPropertyList:@{@"schema": @(schema), @"pid": @(pid),
        @"width": @(width), @"height": @(height), @"prints": prints,
        @"background": [NSMutableData dataWithLength:width * height * 2]}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
}

