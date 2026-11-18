#pragma once
#include <sys/proc.h>
using kauth_cred_t = NativeTestProcess *;
kauth_cred_t kauth_cred_proc_ref(proc_t);
uid_t kauth_cred_getuid(kauth_cred_t);
void kauth_cred_unref(kauth_cred_t *);
