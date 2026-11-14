#ifndef ELAN_AUTH_SUBMISSION_H
#define ELAN_AUTH_SUBMISSION_H
#include <Security/AuthorizationPlugin.h>
#include <Security/AuthorizationTags.h>

/* A following builtin:authenticate,privileged mechanism must validate these credentials. */
static inline OSStatus elan_auth_submit(const AuthorizationCallbacks *callbacks, AuthorizationEngineRef engine,
                                      const char *username, void *password, size_t length) {
    if(!username || !username[0] || !password || !length || length>ElanAuthMaxPassword)
        return errAuthorizationInvalidPointer;
    AuthorizationValue name={strlen(username),(void *)username}, secret={length,password};
    OSStatus status=callbacks->SetContextValue(engine,kAuthorizationEnvironmentUsername,kAuthorizationContextFlagVolatile,&name);
    if(status==errAuthorizationSuccess)
        status=callbacks->SetContextValue(engine,kAuthorizationEnvironmentPassword,kAuthorizationContextFlagVolatile,&secret);
    if(status!=errAuthorizationSuccess && callbacks->version>=4 && callbacks->RemoveContextValue) {
        callbacks->RemoveContextValue(engine,kAuthorizationEnvironmentUsername);
        callbacks->RemoveContextValue(engine,kAuthorizationEnvironmentPassword);
    }
    return status;
}
#endif
