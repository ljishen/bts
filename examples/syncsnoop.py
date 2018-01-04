#!/usr/bin/python
#
# syncsnoop.py    Trace time and count between syncs.
#                 For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time and count between sync events.
#
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, vc, *tsp, *vcp, delta, key_time = 0, key_count = 1;

    vcp = last.lookup(&key_count);
    if (vcp != 0)
        vc = *vcp + 1;
    else
        vc = 1;

    // attempt to read stored timestamp
    tsp = last.lookup(&key_time);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d %d\\n", vc, delta / 1000000);

            vc = 0;
        }

        last.delete(&key_count);
        last.delete(&key_time);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key_time, &ts);

    last.update(&key_count, &vc);

    return 0;
}
""")

b.attach_kprobe(event="sys_sync", fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    (vc, ms) = msg.split()
    print("At time %.2f s: %s syncs detected, last %s ms ago" % (ts, vc, ms))
