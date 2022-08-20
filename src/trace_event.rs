use chrono::prelude::{DateTime,Utc};
use nix::unistd::{Pid};
use std::fmt;
use libc::user_regs_struct;
use syscalls::Sysno;

pub mod wrap_cmd;

pub use wrap_cmd::WrapCmd;

/*
 * Basic tracing event object - this object encapsulates a syscall event, including the time that
 * it was issued as well as the syscall value and any arguments provided to it, stored as a list of
 * string values.
 */
pub struct TraceEvent {
    syscall: Sysno,
    pid: Pid,
    args: Option<Vec<String>>,
    ts: DateTime<Utc>,
}

impl TraceEvent {
    /*
     * A function that will inspect the "regs" provided by a call to ptrace::getregs, which yields
     * a user_regs_struct object. It will look at the registers, and also make some cross-process
     * read calls in order to extract argument values.
     *
     * A great reference to the syscalls is available here:
     * - https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
     *
     */
    fn from_regs(regs: user_regs_struct, pid: Pid) -> Option<TraceEvent> {
        if let Some(syscall) = Sysno::new(regs.orig_rax as usize) {
            match syscall {
                Sysno::open|Sysno::creat|Sysno::unlink => {
                    let ev = TraceEvent {
                        syscall,
                        args: Some(vec![WrapCmd::read_string_arg(pid, regs.rdi)]),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                Sysno::openat|Sysno::unlinkat => {
                    let ev = TraceEvent {
                        syscall,
                        args: Some(vec![WrapCmd::read_string_arg(pid, regs.rsi)]),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                Sysno::link|Sysno::symlink => {
                    let ev = TraceEvent {
                        syscall,
                        args: Some(vec![WrapCmd::read_string_arg(pid, regs.rdi),
                                        WrapCmd::read_string_arg(pid, regs.rdi)]),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                Sysno::linkat => {
                    let ev = TraceEvent {
                        syscall,
                        args: Some(vec![WrapCmd::read_string_arg(pid, regs.rsi),
                                        WrapCmd::read_string_arg(pid, regs.r10)]),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                Sysno::symlinkat => {
                    let ev = TraceEvent {
                        syscall,
                        args: Some(vec![WrapCmd::read_string_arg(pid, regs.rdi),
                                        WrapCmd::read_string_arg(pid, regs.rdx)]),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                Sysno::execve => {
                    let mut argstr: Vec<String> = vec![];
                    let mut argarrptr = regs.rsi;
                    while let Ok(argptr) = WrapCmd::read_long_arg(pid, argarrptr) {
                        if argptr == 0 {
                            break;
                        };
                        argstr.push(WrapCmd::read_string_arg(pid, argptr as u64));
                        argarrptr += 8;
                    };
                    let ev = TraceEvent {
                        syscall,
                        args: Some(argstr),
                        ts: Utc::now(),
                        pid,
                    };
                    Some(ev)
                },
                _ => {
                    None
                }
            }
        } else {
            None
        }
    }
}

/*
 * Will turn a TraceEvent into a Display-able object, such as to be used with println!() or
 * format!()
 */
impl fmt::Display for TraceEvent  {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = write!(f, "{}({},pid={})", &self.syscall, self.syscall as usize, self.pid);
        match &self.args {
            Some(args) => {
                for arg in args.iter() {
                    r = write!(f, " \"{}\"", arg);
                }
            },
            None => {
            }
        }
        r
    }
}
