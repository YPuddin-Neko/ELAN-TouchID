#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ElanNativeProbe.h"
#include "NativeCredentialStudy.h"

static int runStudy(io_connect_t connection, uint32_t selector) {
    NativeCredentialStudyReport report {};
    size_t length = sizeof(report);
    kern_return_t status = IOConnectCallStructMethod(connection, selector, nullptr, 0, &report, &length);
    printf("ELAN_CREDENTIAL_STUDY call_status=0x%x abi=%u length=%zu completed=0x%x\n",
           status, report.abi, length, report.completedSteps);
    for (unsigned i = 0; i < StudyStepCount; i++)
        if (report.completedSteps & (1U << i)) printf("ELAN_CREDENTIAL_STEP index=%u status=%d\n", i, report.stepStatus[i]);
    printf("ELAN_CREDENTIAL_POLICY empty=%u unavailable=%u control=%u matched=%u wrong_user=%u\n",
           report.policySatisfied[0], report.policySatisfied[1], report.policySatisfied[2],
           report.policySatisfied[3], report.policySatisfied[4]);
    printf("ELAN_CREDENTIAL_CLEANUP added=%u created=%u deleted=%u target_delete=%d control_delete=%d\n",
           report.credentialsAdded, report.contextsCreated, report.contextsDeleted,
           report.targetDeleteStatus, report.controlDeleteStatus);
    printf("ELAN_CREDENTIAL_AVAILABILITY before=%u after=%u value_was_present=%u write_attempted=%u restore=%d readback=%d pending=%u\n",
           report.availabilityBefore, report.availabilityAfter, report.availabilityValueWasPresent,
           report.availabilityWriteAttempted, report.restoreStatus, report.readbackStatus, report.availabilityRestorePending);
    bool valid = !status && length == sizeof(report) && report.abi == 1 && report.passed;
    printf("ELAN_CREDENTIAL_STUDY_DONE passed=%d external_contexts=0 system_authorization_requested=0\n", valid);
    return valid ? 0 : 1;
}

int main(int argc, char **argv) {
    bool lifecycle = argc == 2 && !strcmp(argv[1], "--context-lifecycle");
    uint32_t study = argc != 2 ? 0 : !strcmp(argv[1], "--credential-study") ? ElanProbeCredentialStudy :
        !strcmp(argv[1], "--policy-study") ? ElanProbePolicyStudy :
        !strcmp(argv[1], "--restore-study-availability") ? ElanProbeRestoreAvailability : 0;
    if (argc != 2 || (!lifecycle && !study && strcmp(argv[1], "--status"))) {
        fprintf(stderr, "Usage: %s --status | --context-lifecycle | --credential-study | --policy-study | --restore-study-availability\n", argv[0]);
        return 2;
    }
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(ELAN_NATIVE_PROBE_SERVICE));
    if (!service) { puts("ELAN_KERNEL_PROBE service_present=0"); return 3; }
    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t status = IOServiceOpen(service, mach_task_self(), 0, &connection);
    IOObjectRelease(service);
    if (status) { printf("ELAN_KERNEL_PROBE open_status=0x%x uid=%u\n", status, getuid()); return 4; }
    if (study) {
        int result = runStudy(connection, study);
        IOServiceClose(connection);
        return result;
    }
    ElanNativeProbeReport report {};
    size_t length = sizeof(report);
    status = IOConnectCallStructMethod(connection, lifecycle ? ElanProbeContextLifecycle : ElanProbeStatus,
                                      nullptr, 0, &report, &length);
    IOServiceClose(connection);
    printf("ELAN_KERNEL_PROBE call_status=0x%x abi=%u ready=%u uuid=%u symbols=0x%x length=%zu\n",
           status, report.abi, report.ready, report.uuidMatched, report.symbols, length);
    printf("ELAN_KERNEL_STAGES lilu=%u plugin=%u registered=%u callback=%u acm=%u workloop=%u\n",
           !!(report.stages & ElanStageLiluStarted), !!(report.stages & ElanStagePluginEntered),
           !!(report.stages & ElanStageCallbackRegistered), !!(report.stages & ElanStageCallbackSeen),
           !!(report.stages & ElanStageACMPresent), !!(report.stages & ElanStageWorkLoopPresent));
    printf("ELAN_KERNEL_PERMISSIONS status=%d required=0x%016llx\n", report.permissionsStatus,
           static_cast<unsigned long long>(report.requiredPermissions));
    printf("ELAN_KERNEL_AVAILABILITY status=%d value=%u\n", report.availabilityStatus, report.availability);
    printf("ELAN_KERNEL_CONTEXT create=%d delete=%d created=%u deleted=%u\n",
           report.createStatus, report.deleteStatus, report.contextsCreated, report.contextsDeleted);
    bool valid = !status && length == sizeof(report) && report.abi == ELAN_NATIVE_PROBE_ABI && report.ready &&
                 !report.permissionsStatus && !report.availabilityStatus;
    if (lifecycle) valid = valid && !report.createStatus && !report.deleteStatus && report.contextsCreated == 1 && report.contextsDeleted == 1;
    printf("ELAN_KERNEL_PROBE_DONE status=%d credentials_added=0 global_availability_written=0\n", valid ? 0 : 1);
    return valid ? 0 : 1;
}
