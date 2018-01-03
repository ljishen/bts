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

# load BPF program
b = BPF(text="""
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
    u64 *tsp, delta;
    u32 *bsp;

    u32 pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    bsp = size.lookup(&pid);

    if (tsp != 0 && bsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("%d %s %d\\n", *bsp, args->rwbs,
            delta / 1000);

        start.delete(&pid);
        size.delete(&pid);
    }

    return 0;
}
""")

# header
print("%-18s %-6s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    (bytes_s, rwbs_s, us_s) = msg.split()

    ms = float(int(us_s, 10)) / 1000

    print("%-18.9f %-6s %-7s %8.2f" % (ts, rwbs_s, bytes_s, ms))
