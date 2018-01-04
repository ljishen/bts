#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Require Linux >= 4.7 (BPF_PROG_TYPE_TRACEPOINT support).
#
# Copyright (c) 2018 Jianshen Liu.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 02-Jan-2018	Jianshen Liu	Created this.

from __future__ import print_function
from bcc import BPF

import ctypes as ct

# load BPF program
b = BPF(text="""
#include <linux/sched.h>
#include <trace/events/block.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
    u32 bytes;
    char rwbs[RWBS_LEN];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

BPF_HASH(start, u32);
BPF_HASH(size, u32, u32);

TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);

    u32 bs = args->bytes;
    size.update(&pid, &bs);

    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    struct data_t data = {};
    u64 *tsp;
    u32 *bsp;

    data.pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&data.pid);
    bsp = size.lookup(&data.pid);

    if (tsp != 0 && bsp != 0) {
        data.ts = bpf_ktime_get_ns();
        data.delta = (data.ts - *tsp) / 1000;
        data.bytes = *bsp;
        bpf_probe_read(data.rwbs, sizeof(args->rwbs), args->rwbs);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(args, &data, sizeof(data));

        start.delete(&data.pid);
        size.delete(&data.pid);
    }

    return 0;
}
""")

# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
RWBS_LEN = 8  # trace/events/block.h


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint), ("ts", ct.c_ulonglong),
                ("delta", ct.c_ulonglong), ("bytes", ct.c_uint),
                ("rwbs", ct.c_char * RWBS_LEN), ("comm",
                                                 ct.c_char * TASK_COMM_LEN)]


# header
print("%-18s %-8s %-16s %-8s %-16s %6s" % ("TIME(s)", "PID", "COMM", "T",
                                           "BYTES", "LAT(ms)"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    ms = float(event.delta) / 1000
    print("%-18.9f %-8d %-16s %-8s %-16d %-6.3f" %
          (time_s, event.pid, event.comm, event.rwbs, event.bytes, ms))


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
