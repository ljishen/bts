#!/usr/bin/python
#
# disklatency.py	Trace block device I/O: basic version of iosnoop.
#			For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of summarize I/O latency.
#
# Copyright (c) 2018 Jianshen Liu.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 01-Jan-2018	Jianshen Liu	Created this.

from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();

	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;

	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
                dist.increment(bpf_log2l(delta / 1000));
		start.delete(&req);
	}
}
""")

b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    print

# output
b["dist"].print_log2_hist("microseconds")
