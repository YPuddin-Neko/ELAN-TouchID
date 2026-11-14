#include "kernel-provider/NativeLACRetry.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
static int readOwn(void *, uint64_t address, void *bytes, size_t length) {
    mach_vm_size_t count = 0;
    int status = mach_vm_read_overwrite(mach_task_self(), address, length, reinterpret_cast<mach_vm_address_t>(bytes), &count);
    return status ? status : count == length ? 0 : -1;
}
static int writeOwn(void *, uint64_t address, const void *bytes, size_t length) {
    return mach_vm_write(mach_task_self(), address, reinterpret_cast<vm_offset_t>(bytes), static_cast<mach_msg_type_number_t>(length));
}
static bool writableOwn(void *, uint64_t address, size_t length) {
    mach_vm_address_t start = address; mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info {};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    int status = mach_vm_region(mach_task_self(), &start, &size, VM_REGION_BASIC_INFO_64,
                               reinterpret_cast<vm_region_info_t>(&info), &count, &object);
    if (object) mach_port_deallocate(mach_task_self(), object);
    return !status && (info.protection & VM_PROT_WRITE) && start <= address && address - start <= size && length <= size - (address - start);
}
extern "C" int elanRetryOwnHelper(uint64_t instance, uint64_t fault, uint64_t permanent, uint64_t helperClass) {
    NativePlatformCacheAPI api {nullptr, readOwn, writeOwn, writableOwn};
    NativeLACRetryRequest request {instance, fault, permanent, helperClass};
    NativeLACRetryState state {};
    int prepared = nativeLACRetryPrepare(api, request, state);
    int transferred = prepared ? prepared : nativeLACRetryTransfer(api, state);
    printf("LAC_RETRY prepared=%d transferred=%d process_exit_required=%d system_processes_touched=0\n",
           prepared, transferred, state.restartRequired);
    return transferred;
}
