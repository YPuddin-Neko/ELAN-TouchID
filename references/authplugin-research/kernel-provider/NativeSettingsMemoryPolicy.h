#pragma once
#include <stdint.h>

namespace NativeSettingsMemoryPolicy {
// A writable data mapping can have an executable maximum without being executable.
// No protection changes are made here; unknown bits and current execute access fail.
inline bool writableData(uint32_t protection, uint32_t maximum, bool copyOnWrite) {
    constexpr uint32_t readWrite = 3, readWriteExecute = 7;
    return copyOnWrite && protection == readWrite &&
           (maximum == readWrite || maximum == readWriteExecute);
}
}
