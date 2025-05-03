use drcomrs::{load_config, login_and_keep, run_interactive, Config, NetworkError, Result};
use std::{env, thread::sleep, time::Duration};
use NetworkError::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut interactive = false;
    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-i" => {
                interactive = true;
            }
            _ => {
                eprintln!("Invalid Argument: {}", arg);
                print_help();
                return Ok(());
            }
        }
    }
    let config = load_config();
    if config.is_err() || interactive {
        let cfg = run_interactive()?;
        mainloop(&cfg)?;
    } else {
        let cfg = config?;
        mainloop(&cfg)?;
    }

    Ok(())
}

fn print_help() {
    println!("-i         Interactive");
}

fn mainloop(config: &Config) -> Result<()> {
    loop {
        match login_and_keep(config) {
            Err(e) => match e {
                LoginError | LogoutError|LogoutSuccess => return Err(Box::new(e)),
                _ => {
                    println!("Err:{:?}", e);
                }
            },
            _ => {}
        }
        sleep(Duration::from_secs(5));
    }
}
