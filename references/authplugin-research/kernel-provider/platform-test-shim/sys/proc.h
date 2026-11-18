#pragma once
#include <sys/types.h>
struct NativeTestProcess;
using proc_t = NativeTestProcess *;
proc_t proc_find(int);
void proc_rele(proc_t);
int proc_name(int, void *, int);
