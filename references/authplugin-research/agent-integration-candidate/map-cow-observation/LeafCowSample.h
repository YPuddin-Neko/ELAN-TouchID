#pragma once
#include <stdint.h>
#include <stddef.h>
#include <mach/vm_region.h>
namespace LeafCowSample {
static_assert(sizeof(vm_region_submap_short_info_data_64_t)==48, "Pinned short-info ABI size");
static_assert(VM_REGION_SUBMAP_SHORT_INFO_COUNT_64==12, "Pinned short-info ABI count");
static_assert(offsetof(vm_region_submap_short_info_data_64_t, offset)==12, "Pinned offset ABI");
static_assert(offsetof(vm_region_submap_short_info_data_64_t, share_mode)==31, "Pinned share-mode ABI");
static_assert(offsetof(vm_region_submap_short_info_data_64_t, is_submap)==32, "Pinned submap ABI");
// The adapter is callable only after the exact kernel code pins are checked.
using Query = int (*)(void *, uint64_t *, uint64_t *, unsigned *, vm_region_submap_info_64_t, unsigned *);
enum class Status : uint32_t { Argument, QueryFailed, Count, Depth, Coverage, Submap, Protection, Sharing, Cow };
struct Result {
 Status status=Status::Argument;
 uint32_t depth=0, protection=0, maxProtection=0, shareMode=0, shadowDepth=0;
 bool cow() const { return status==Status::Cow; }
};
inline Result inspect(Query query, void *retainedMap, uint64_t address) {
 Result out{};
 constexpr uint64_t limit=0x00007fffffffffffULL;
 constexpr unsigned maxDepth=8;
 if(!query || !retainedMap || address<4096 || address>=limit) return out;
 uint64_t start=address, size=0;
 unsigned depth=maxDepth, count=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
 vm_region_submap_short_info_data_64_t info{};
 if(query(retainedMap,&start,&size,&depth,reinterpret_cast<vm_region_submap_info_64_t>(&info),&count)!=0) {
  out.status=Status::QueryFailed; return out;
 }
 if(count!=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {out.status=Status::Count;return out;}
 out.depth=depth;
 if(depth>maxDepth) {out.status=Status::Depth;return out;}
 if(start>address || size<2 || start>UINT64_MAX-size || address-start>size-2) {
  out.status=Status::Coverage;return out;
 }
 if(info.is_submap) {out.status=Status::Submap;return out;}
 out.protection=info.protection;out.maxProtection=info.max_protection;
 out.shareMode=info.share_mode;out.shadowDepth=info.shadow_depth;
 if((info.protection&VM_PROT_ALL)!=(VM_PROT_READ|VM_PROT_WRITE) ||
    (info.max_protection&(VM_PROT_READ|VM_PROT_WRITE))!=(VM_PROT_READ|VM_PROT_WRITE)) {
  out.status=Status::Protection;return out;
 }
 out.status=info.share_mode==SM_COW?Status::Cow:Status::Sharing;
 return out;
}
}
