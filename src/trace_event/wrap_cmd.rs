use nix::sys::ptrace;
use nix::unistd::{Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use fork::{fork, Fork};
use exec::Command;
use std::thread;
use std::sync::mpsc;
use std::time::Duration;
use std::sync::{Arc,Mutex};
use std::collections::HashSet;

pub use super::TraceEvent;

struct WrapCmdShared {
    do_exit: bool,
}

/*
 * This data structure provides a wrapper around the context of the command we are executing &
 * inspecting.
 */
pub struct WrapCmd {
    prog: String,
    args: Vec<String>,
    pid: Pid,
    shdata: Arc<Mutex<WrapCmdShared>>,
    syscall_entered: HashSet<Pid>,
    //service_thread_handle: Option<thread::JoinHandle<()>>,
}

/*
 * Shared data that is meant to be accessible both from the code monitoring the process as well as
 * the code that is writing the events to long term storage (or other destination) should be placed
 * here.
 */
impl WrapCmdShared {
    pub fn set_exit(self: &mut Self) {
        self.do_exit = true;
    }
    pub fn unset_exit(self: &mut Self) {
        self.do_exit = false;
    }
}

impl WrapCmd {
    pub fn new(args: Vec<String>) -> Self {
        Self {
            prog: String::from(args.get(0)
                               .expect("There must be at least a program name")),
            args: if args.len() < 2 {
                vec![]
            } else {
                args.get(1..args.len())
                    .expect("Problem parsing cmd args").to_vec()
            },
            pid: Pid::from_raw(-1),
            shdata: Arc::new(Mutex::new(WrapCmdShared {
                do_exit: true,
            })),
            syscall_entered: HashSet::new(),
            //service_thread_handle: None,
        }
    }

    pub fn wait_finish(self: &mut Self, tx: &mpsc::Sender<TraceEvent>) -> Result<WaitStatus, nix::Error> {
        let ws = match waitpid(Pid::from_raw(-1), None) {
            Err(e) => {
                match e {
                    nix::errno::Errno::ECHILD => {
                        panic!("Wait faild")
                    },
                    _ => {
                        Ok(WaitStatus::Exited(self.pid, 0))
                    },
                }
            },
            Ok(w) => {
                Ok(w)
            }
        };
        match ws {
            Ok(WaitStatus::Exited(epid, r)) => {
                println!("Exited: pid={} {}", epid, r);
                ptrace::detach(epid, None);
                waitpid(epid, None);
                if epid == self.pid {
                    self.shdata.lock().unwrap().set_exit();
                };
            },
            Ok(WaitStatus::Stopped(epid, s)) => {
                println!("Stopped: pid={} {}", epid, s);
                if let Err(e) = ptrace::syscall(epid, s) {
                    println!("Error re-starting trace after signal");
                }
            },
            Ok(WaitStatus::Signaled(epid, s, b)) => {
                println!("Sigged: {} {}", s, b);
                if let Err(e) = ptrace::syscall(epid, s) {
                    println!("Error re-starting trace after kill");
                }
            },
            Ok(WaitStatus::PtraceEvent(epid, s, i)) => {
                println!("ptrace Event: {} / {}", s, i);
                if (i > 0) && (i < 4) {
                    if let Ok(cpid) = ptrace::getevent(epid) {
                        println!("CPID: {}", cpid);
                        waitpid(Pid::from_raw(cpid as i32), None);
                        if let Err(e) = ptrace::syscall(Pid::from_raw(cpid as i32), None) {
                            println!("Error starting trace in subproc");
                        }
                    };
                    if let Err(e) = ptrace::syscall(epid, None) {
                        println!("Error re-starting trace on OG proc");
                    }
                } else if i == 4 {
                    if let Err(e) = ptrace::syscall(epid, None) {
                        println!("Error re-starting trace on OG proc");
                    }
                } else if i == 6 {
                    println!("waiting");
                    ptrace::cont(epid, None);
                    println!("Successfully waited");
                };
            },
            Ok(WaitStatus::PtraceSyscall(epid)) => {
                //println!("ptrace Syscall");
                if let Ok(regs) = ptrace::getregs(epid) {
                    let ev = TraceEvent::from_regs(regs, epid);

                    match ev {
                        Some(bundle) => {
                            if self.syscall_entered.contains(&epid) {
                                self.syscall_entered.remove(&epid);
                            } else {
                                self.syscall_entered.insert(epid);
                                tx.send(bundle).unwrap();
                            }
                        },
                        None => {
                            // If we get a None, it is because the Syscall isn't
                            // instrumented, and we just silently move right along
                        },
                    }

                    //println!("Syscall: {}", regs.orig_rax);
                } else {
                    //println!("Couldn't read regs!");
                }
                ptrace::syscall(epid, None);
            },
            Ok(WaitStatus::Continued(epid)) => {
                println!("Continued!");
            },
            Ok(WaitStatus::StillAlive) => {
                println!("Stayin alive!");
            },
            _ => {  },
        };

        ws

    }

    fn service_thread(inner: Arc<Mutex<WrapCmdShared>>, rx: mpsc::Receiver<TraceEvent>) {
        let mut events: Vec<TraceEvent> = vec![];
        println!("Thread hi!");
        while (*inner).lock().unwrap().do_exit == false {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(1000)) {
                events.push(ev);
            };
        };

        println!("Events: {}", events.len());

        for (_, e) in events.iter().enumerate() {
            println!("Syscall: {}", e);
        };
    }

    pub fn read_long_arg(pid: Pid, mut addr: u64) -> Result<i64, nix::Error> {
        ptrace::read(pid, addr as *mut core::ffi::c_void)
    }

    pub fn read_string_arg(pid: Pid, mut addr: u64) -> String {
        let mut res = String::from("");

        while let Ok(val) = WrapCmd::read_long_arg(pid, addr) {
            let substr = val.to_le_bytes().to_vec().split(|n| n == &0).next().unwrap().to_vec();

            let newstr = String::from_utf8(substr).unwrap();
            let oldlen = res.len();
            res += newstr.as_str();

            // If we got a short string, then it is the terminal
            if res.len() < oldlen + 8 {
                return res;
            }

            addr += 8;
        }

        res
    }

    pub fn start_child(self: &mut Self) {
        self.shdata.lock().unwrap().unset_exit();
        match fork() {
            Ok(Fork::Parent(child)) => {
                println!("Forked child process({})", child);
                self.pid = Pid::from_raw(child);
                let (tx, rx) = mpsc::channel();
                waitpid(self.pid, None);
                //let ws = self.wait_finish(&tx).expect("Tracing starting");

                /*
                 * The below code asks for ptrace to be set up on the process with the following
                 * attributes:
                 *
                 * Report ptrace events as PTRACE_EVENT_* flags in the signal to waitpid()
                 * Trace execve, fork, clone, and vforks
                 * Kill tracees on exit from monitor
                 * Generate a trace event on exit of a traced process.
                 */
                ptrace::setoptions(self.pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | 
                                             ptrace::Options::PTRACE_O_EXITKILL     |
                                             ptrace::Options::PTRACE_O_TRACEEXEC    |
                                             ptrace::Options::PTRACE_O_TRACEFORK    |
                                             ptrace::Options::PTRACE_O_TRACEVFORK   |
                                             ptrace::Options::PTRACE_O_TRACEVFORKDONE |
                                             ptrace::Options::PTRACE_O_TRACECLONE   |
                                             ptrace::Options::PTRACE_O_TRACEEXIT)
                    .expect("There was an error setting ptrace options");

                let cloned_inner = self.shdata.clone();

                let service_thread_handle = Some(thread::spawn(move || { WrapCmd::service_thread(cloned_inner, rx) }));

                let mut stopped_pid = self.pid;

                /* 
                 * This "if" is the initial kick-off to tracing. After this, the wait_finish
                 * handler will coordinate further calls to continue tracing.
                 */
                if let Ok(r) = ptrace::syscall(self.pid, None) {
                    while self.shdata.lock().unwrap().do_exit == false {
                        let ws = self.wait_finish(&tx).expect("Error in waitpid()");

                    };
                };

                service_thread_handle.unwrap().join().expect("Failed to join thread");
                println!("Service Thread Joined");
            },
            Ok(Fork::Child) => {
                ptrace::traceme().expect("Could not enable tracing for child");
                println!("Executing child process: {} {:?}", self.prog, self.args);
                let mut cmd = Command::new(&self.prog);
                if self.args.len() > 0 {
                    cmd.args(&self.args);
                }
                println!("Error: {}", cmd.exec());
            },
            Err(_) => println!("Could not fork!"),
        }
    }
}
