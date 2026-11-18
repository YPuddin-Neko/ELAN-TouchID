#pragma once
#include "NativeSettingsEndpoint.h"

namespace NativeSettingsRoute {
enum class Result { Skipped, Routed, Restored, Incomplete };
constexpr uint64_t pageSize = 4096;

// Called on the admitted Settings main thread before either discovery singleton is initialized.
// The kernel backend never receives a destination address from a user client.
template<class Memory>
Result apply(Memory &memory, uint64_t cacheBase) {
    NativeSettingsEndpoint::Location location{};
    if (!NativeSettingsEndpoint::locate(memory.reader(),cacheBase,location)) return Result::Skipped;
    const uint64_t flags = cacheBase + 0x10a5b0000ULL + 0x38e1b028ULL;
    const uint64_t page = location.slot & ~(pageSize-1);
    const uint8_t original[] = {0,0}, enabled[] = {1,1};
    if (!memory.permitted() || !memory.cowSlot(location.slot) ||
        !memory.writableData(flags) || !memory.reader().equal(flags,original,2)) return Result::Skipped;

    uint64_t storage = 0;
    if (!memory.allocate(storage)) return Result::Skipped;
    const auto name = reinterpret_cast<const uint8_t *>(NativeSettingsEndpoint::serviceName);
    const size_t length = sizeof(NativeSettingsEndpoint::serviceName);
    if (!memory.write(storage,name,length) || !memory.seal(storage) ||
        !memory.reader().equal(storage,name,length) || !memory.permitted()) {
        return memory.release(storage) ? Result::Restored : Result::Incomplete;
    }
    if (!memory.makeCopyWritable(page)) {
        const bool protectedAgain = memory.readOnlySlot(location.slot) || memory.protectSlot(page);
        const bool released = memory.release(storage);
        return protectedAgain && released ? Result::Restored : Result::Incomplete;
    }
    uint64_t current = 0;
    bool published = false, flagsAttempted = false;
    if (memory.reader().read(location.slot,&current,sizeof(current)) && current == location.original &&
        memory.permitted()) {
        published = memory.storePointer(location.slot,storage);
    }
    if (memory.protectSlot(page) && memory.readOnlySlot(location.slot) && published &&
        memory.reader().read(location.slot,&current,sizeof(current)) && current == storage &&
        memory.permitted() && memory.reader().equal(flags,original,2)) {
        flagsAttempted = true;
        if (memory.write(flags,enabled,2) && memory.reader().equal(flags,enabled,2) &&
            memory.permitted()) return Result::Routed;
    }
    bool cacheRestored = true;
    if (flagsAttempted) {
        memory.write(flags,original,2);
        cacheRestored = memory.reader().equal(flags,original,2);
    }
    if (!memory.reader().read(location.slot,&current,sizeof(current))) return Result::Incomplete;
    if (current == storage) {
        if (!memory.makeCopyWritable(page)) return Result::Incomplete;
        memory.storePointer(location.slot,location.original);
    }
    const bool readOnly = memory.protectSlot(page) && memory.readOnlySlot(location.slot);
    if (!memory.reader().read(location.slot,&current,sizeof(current)) || current != location.original)
        return Result::Incomplete; // A potentially referenced name lives as long as its owning task.
    const bool released = memory.release(storage);
    return cacheRestored && readOnly && released ? Result::Restored : Result::Incomplete;
}
}
