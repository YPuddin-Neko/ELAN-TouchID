#pragma once
#include <stdint.h>
using kauth_cred_t = void *;
using kauth_action_t = int;
struct kauth_listener {};
using kauth_listener_t = kauth_listener *;
using kauth_scope_callback_t = int (*)(kauth_cred_t,void *,kauth_action_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t);
#define KAUTH_FILEOP_EXEC 6
#define KAUTH_RESULT_DEFER 3
#define KAUTH_SCOPE_FILEOP "com.apple.kauth.fileop"
kauth_listener_t kauth_listen_scope(const char *,kauth_scope_callback_t,void *);
void kauth_unlisten_scope(kauth_listener_t);
