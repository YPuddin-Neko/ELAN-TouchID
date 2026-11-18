#include <IOKit/usb/IOUSBHostDevice.h>
#include <IOKit/usb/IOUSBHostInterface.h>
#include <mach/kmod.h>
#include "SensorProfile.h"

class ELANFingerprintUSB : public IOService {
    OSDeclareDefaultStructors(ELANFingerprintUSB)
public:
    bool start(IOService *provider) override;
};
OSDefineMetaClassAndStructors(ELANFingerprintUSB, IOService)

bool ELANFingerprintUSB::start(IOService *provider) {
    auto *usb = OSDynamicCast(IOUSBHostInterface, provider);
    if (!usb || !usb->getDevice()) return false;
    auto *device = usb->getDevice()->getDeviceDescriptor();
    auto *interface = usb->getInterfaceDescriptor();
    auto *config = usb->getConfigurationDescriptor();
    if (!device || !interface || !config ||
        USBToHost16(device->idVendor) != elan::vendor || USBToHost16(device->idProduct) != elan::product ||
        interface->bInterfaceNumber != 0 || interface->bAlternateSetting != 0 ||
        !elan::hasSensorInterface(reinterpret_cast<const uint8_t *>(config), USBToHost16(config->wTotalLength)))
        return false;
    if (!IOService::start(provider)) return false;
    registerService();
    return true;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(io.github.hackintosh-tools.elan-fingerprint-usb, "0.1.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = nullptr;
__private_extern__ kmod_stop_func_t *_antimain = nullptr;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
}
