#pragma once
#include <stdint.h>
#include <stddef.h>

static inline uint32_t nativeSliceU32(const uint8_t *p, bool big) {
    return big ? uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]
               : uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0];
}
static inline uint64_t nativeSliceU64(const uint8_t *p, bool big) {
    return big ? uint64_t(nativeSliceU32(p, true)) << 32 | nativeSliceU32(p + 4, true)
               : uint64_t(nativeSliceU32(p + 4, false)) << 32 | nativeSliceU32(p, false);
}

// read(offset, bytes, count) must return true only after reading the entire range.
// Select one native 64-bit executable slice. Ambiguous or malformed images fail closed.
template <typename Read>
static bool nativeExecutableSlice(uint64_t fileSize, uint32_t cpu, Read read, uint64_t &offset) {
    offset = 0;
    uint8_t header[32] = {};
    if (fileSize < sizeof(header) || !read(0, header, sizeof(header))) return false;
    uint32_t magic = nativeSliceU32(header, true);
    uint64_t start = 0, length = fileSize;
    if (magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca) {
        bool big = magic == 0xcafebabe || magic == 0xcafebabf;
        bool wide = magic == 0xcafebabf || magic == 0xbfbafeca;
        uint32_t count = nativeSliceU32(header + 4, big);
        uint64_t entrySize = wide ? 32 : 20;
        uint64_t tableEnd = 8 + uint64_t(count) * entrySize;
        if (!count || count > 64 || tableEnd > fileSize) return false;
        unsigned matches = 0;
        for (uint32_t i = 0; i < count; i++) {
            uint8_t entry[32] = {};
            if (!read(8 + uint64_t(i) * entrySize, entry, size_t(entrySize))) return false;
            uint64_t at = wide ? nativeSliceU64(entry + 8, big) : nativeSliceU32(entry + 8, big);
            uint64_t size = wide ? nativeSliceU64(entry + 16, big) : nativeSliceU32(entry + 12, big);
            uint32_t alignment = nativeSliceU32(entry + (wide ? 24 : 16), big);
            if (alignment > 31 || at < tableEnd || at > fileSize || size < sizeof(header) || size > fileSize - at ||
                at % (uint64_t(1) << alignment) || (wide && nativeSliceU32(entry + 28, big))) return false;
            if (nativeSliceU32(entry, big) == cpu) { matches++; start = at; length = size; }
        }
        if (matches != 1 || !read(start, header, sizeof(header))) return false;
    }
    // Mach-O 64, little-endian, matching architecture, MH_EXECUTE, bounded commands.
    if (nativeSliceU32(header, false) != 0xfeedfacf || nativeSliceU32(header + 4, false) != cpu ||
        nativeSliceU32(header + 12, false) != 2 || nativeSliceU32(header + 20, false) > length - sizeof(header)) return false;
    offset = start;
    return true;
}
