// Include after the shared ELAN transport and capture implementation.
static int prepareEnrollmentBackgroundWithReader(Sensor *s, int existingBackground, unsigned calibrationMean,
                                                int (*readFrame)(Sensor *, unsigned short *)) {
    size_t pixels = (size_t)s->w * s->hgt;
    unsigned short *frameData = calloc(pixels, sizeof(*frameData));
    uint32_t *sum = calloc(pixels, sizeof(*sum));
    unsigned accepted = 0;
    time_t deadline = time(NULL) + capture_timeout_seconds;
    capture_last_result = ElanCapturePending;
    if (!frameData || !sum) { capture_last_result = ElanCaptureAllocationError; goto done; }
    captureEvent(ElanCaptureCalibrating);
    while (!cancelled && time(NULL) < deadline) {
        if (capture_should_cancel && capture_should_cancel()) { capture_last_result = ElanCaptureCancelled; break; }
        if (!readFrame(s, frameData)) { capture_last_result = cancelled ? ElanCaptureCancelled : ElanCaptureDeviceError; break; }
        uint64_t total = 0;
        for (size_t i = 0; i < pixels; i++) total += frameData[i];
        unsigned mean = (unsigned)(total / pixels);
        unsigned delta = mean > calibrationMean ? mean - calibrationMean : calibrationMean - mean;
        ElanpressTouchStats stats;
        int touched = existingBackground && elanpress_frame_has_touch(frameData, s->bg, (int)pixels, &stats);
        if (delta > 500 || touched) {
            accepted = 0; memset(sum, 0, pixels * sizeof(*sum));
            captureEvent(ElanCaptureAwaitRelease);
            continue;
        }
        for (size_t i = 0; i < pixels; i++) sum[i] += frameData[i];
        if (++accepted == 12) {
            for (size_t i = 0; i < pixels; i++) s->bg[i] = (unsigned short)(sum[i] / 12);
            capture_last_result = ElanCaptureSucceeded;
            captureEvent(ElanCaptureReady);
            break;
        }
    }
    if (cancelled) capture_last_result = ElanCaptureCancelled;
    else if (capture_last_result == ElanCapturePending) capture_last_result = ElanCaptureTimedOut;
done:
    if (frameData) { memset(frameData, 0, pixels * sizeof(*frameData)); free(frameData); }
    if (sum) { memset(sum, 0, pixels * sizeof(*sum)); free(sum); }
    return capture_last_result == ElanCaptureSucceeded;
}

static int prepareEnrollmentBackground(Sensor *s, int existingBackground) {
    unsigned char response[2];
    if (!command(s, 0x40, 0x24) || !io(s, 0x83, response, sizeof(response))) {
        capture_last_result = cancelled ? ElanCaptureCancelled : ElanCaptureDeviceError;
        return 0;
    }
    unsigned calibrationMean = (response[0] << 8) | response[1];
    int prepared = prepareEnrollmentBackgroundWithReader(s, existingBackground, calibrationMean, frame);
    printf("ENROLL_BACKGROUND calibration_mean=%u existing=%d prepared=%d result=%u\n",
        calibrationMean, existingBackground, prepared, capture_last_result);
    return prepared;
}
