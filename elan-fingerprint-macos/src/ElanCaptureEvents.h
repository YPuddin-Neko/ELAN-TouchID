#pragma once

typedef enum {
    ElanCaptureAwaitRelease,
    ElanCaptureReady,
    ElanCaptureTouchDetected,
    ElanCaptureTooShort,
    ElanCaptureLowQuality,
    ElanCaptureSampleReady,
    ElanCaptureCalibrating,
} ElanCaptureEvent;

typedef enum {
    ElanCapturePending,
    ElanCaptureSucceeded,
    ElanCaptureCancelled,
    ElanCaptureTimedOut,
    ElanCaptureDeviceError,
    ElanCaptureImageRejected,
    ElanCaptureAllocationError,
} ElanCaptureResult;
