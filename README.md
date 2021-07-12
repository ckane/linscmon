# LinSCMon

NOTE: This is a project I've undertaken to help me learn more about Rust
programming, so keep that in mind. Will gladly take PR's as feedback.

LinSCMon (Linux Syscall Monitor) is a utility intended to facilitate
run-time instrumentation of processes by setting up the execution environment
using selected probe APIs and then forking off the desired process to be
monitored with said probes.

Right now it uses the
[ptrace API](https://docs.rs/nix/latest/nix/sys/ptrace/index.html). This
API is notorious for having a significant performance overhead, as the
calls must be intercepted for all syscalls, and then the monitor must
decide whether to report or not. My aim will be to provide an abstracted
interface that facilitates implementation of other monitoring APIs, such
that ptrace could be used as a last resort, but with a preference for
something like [eBPF](https://ebpf.io/), which as of this writing, I am
still learning, too.

