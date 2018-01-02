#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF

import ctypes as ct

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u64 delta;
    u64 count;
};
BPF_PERF_OUTPUT(events);

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 *tsp, *vcp, key_time = 0, key_count = 1;

    vcp = last.lookup(&key_count);
    if (vcp != 0)
        data.count = *vcp + 1;
    else
        data.count = 1;

    // attempt to read stored timestamp
    tsp = last.lookup(&key_time);
    if (tsp != 0) {
        data.ts = bpf_ktime_get_ns();
        data.delta = (data.ts - *tsp) / 1000000;
        if (data.delta < 1000) {
            // output if time is less than 1 second
            data.pid = bpf_get_current_pid_tgid();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            events.perf_submit(ctx, &data, sizeof(data));

	    data.count = 0;
        }

        last.delete(&key_time);
	last.delete(&key_count);
    }

    // update stored timestamp
    u64 ts = bpf_ktime_get_ns();
    last.update(&key_time, &ts);

    last.update(&key_count, &data.count);

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="sys_sync", fn_name="do_trace")

# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("delta", ct.c_ulonglong),
		("count", ct.c_ulonglong)]

# header
print("%-18s %-16s %-16s %-16s %-6s" % ("TIME(s)", "COMM", "PID", "COUNT", "DELTA(ms)"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-16d %-16d %-6.3f" % (time_s, event.comm, event.pid,
        event.count, event.delta))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
