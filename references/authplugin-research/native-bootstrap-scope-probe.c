#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    mach_port_t requestor = MACH_PORT_NULL, subset = MACH_PORT_NULL, service = MACH_PORT_NULL;
    mach_port_t found = MACH_PORT_NULL, parentFound = MACH_PORT_NULL;
    int result = 1;
    kern_return_t status = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &requestor);
    if (status) return 2;
    status = mach_port_insert_right(mach_task_self(), requestor, requestor, MACH_MSG_TYPE_MAKE_SEND);
    if (!status) status = bootstrap_subset(bootstrap_port, requestor, &subset);
    printf("BOOTSTRAP_SCOPE subset_status=%d distinct=%d\n", status, subset != MACH_PORT_NULL && subset != bootstrap_port);
    if (status || subset == MACH_PORT_NULL || subset == bootstrap_port) goto cleanup;
    status = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &service);
    if (!status) status = mach_port_insert_right(mach_task_self(), service, service, MACH_MSG_TYPE_MAKE_SEND);
    if (status) goto cleanup;
    name_t name;
    snprintf(name, sizeof(name), "io.github.hackintosh-tools.bootstrap-study.%d", getpid());
    status = bootstrap_register(subset, name, service);
    printf("BOOTSTRAP_SCOPE register_status=%d\n", status);
    if (status) goto cleanup;
    status = bootstrap_look_up(subset, name, &found);
    kern_return_t parentStatus = bootstrap_look_up(bootstrap_port, name, &parentFound);
    printf("BOOTSTRAP_SCOPE child_lookup=%d port_matches=%d parent_lookup=%d\n", status, found == service, parentStatus);
    result = !status && found == service && parentStatus == BOOTSTRAP_UNKNOWN_SERVICE ? 0 : 1;
cleanup:
    if (found != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), found);
    if (parentFound != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), parentFound);
    if (service != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), service);
    mach_port_destroy(mach_task_self(), requestor);
    if (subset != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), subset);
    printf("BOOTSTRAP_SCOPE_DONE status=%d apple_service_names_registered=0 task_bootstrap_changed=0\n", result);
    return result;
}
