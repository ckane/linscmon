use std::env;
use ptrace_watch::trace_event::wrap_cmd::WrapCmd;

fn main() {
    let arglist: Vec<String> = env::args().collect();

    let mut wc = WrapCmd::new(arglist.get(1..arglist.len())
                              .expect("There must be at least one argument")
                              .to_vec());
    wc.start_child();

    /*match wc.wait_finish() {
        Ok(_) => println!("Completed!"),
        Err(e) => {
            println!("There was an error: {}", e);
        },
    }*/
}
