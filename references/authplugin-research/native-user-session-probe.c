#include "native-user-session-darwin.h"
#include <stdio.h>
#include <unistd.h>
int main(void) {
    NativeUserSessionSnapshot value = nativeReadUserSession(0);
    printf("{\"process_uid\":%u,\"console_known\":%d,\"console_uid\":%u,\"gui_known\":%d,\"gui_uid\":%u,"
           "\"on_console\":%d,\"login_done\":%d,\"security_known\":%d,\"security_session\":%u,\"graphic_access\":%d,"
           "\"coreauth_pid\":%d,\"coreauth_start_seconds\":%llu,\"coreauth_start_microseconds\":%llu,\"admission\":%u,"
           "\"sensor_opened\":false,\"kernel_opened\":false,\"services_changed\":false}\n",
           getuid(), value.consoleKnown, value.consoleUser, value.guiKnown, value.guiUser, value.onConsole,
           value.loginDone, value.securityKnown, value.securitySession, value.graphicAccess, value.coreauth.pid,
           (unsigned long long)value.coreauth.seconds, (unsigned long long)value.coreauth.microseconds,
           nativeSessionAdmission(value, true));
    return 0;
}
