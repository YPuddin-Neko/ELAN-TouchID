#pragma once
#include <stdint.h>
#include <stddef.h>

namespace elan {
constexpr uint16_t vendor = 0x04f3;
constexpr uint16_t product = 0x0c1a;
constexpr uint8_t commandOut = 0x01;
constexpr uint8_t frameIn = 0x82;
constexpr uint8_t replyIn = 0x83;

inline uint16_t little16(const uint8_t *p) {
    return uint16_t(p[0]) | uint16_t(uint16_t(p[1]) << 8);
}

// Both USBHost and IOUSBLib expose this cached configuration in USB byte order.
inline bool hasSensorInterface(const uint8_t *p, size_t size) {
    if (!p || size < 9 || p[0] < 9 || p[1] != 2 || little16(p + 2) != size || p[5] != 1)
        return false;
    bool inSensor = false, found = false;
    unsigned required = 0, expectedEndpoints = 0, endpoints = 0;
    for (size_t pos = p[0]; pos < size;) {
        if (size - pos < 2) return false;
        const uint8_t *d = p + pos;
        if (d[0] < 2 || d[0] > size - pos) return false;
        if (d[1] == 4) {
            if (d[0] < 9 || (inSensor && endpoints != expectedEndpoints)) return false;
            inSensor = d[2] == 0 && d[3] == 0 && d[5] == 255 && d[6] == 0 && d[7] == 0;
            if (inSensor) {
                if (found) return false;
                found = true;
                expectedEndpoints = d[4];
                endpoints = 0;
            }
        } else if (d[1] == 5 && inSensor) {
            if (d[0] < 7) return false;
            ++endpoints;
            unsigned bit = 0;
            switch (d[2]) {
                case commandOut: bit = 1; break;
                case frameIn: bit = 2; break;
                case replyIn: bit = 4; break;
            }
            if (bit) {
                if ((d[3] & 3) != 2 || little16(d + 4) == 0 || (required & bit)) return false;
                required |= bit;
            }
        }
        pos += d[0];
    }
    return found && required == 7 && endpoints == expectedEndpoints;
}
}
