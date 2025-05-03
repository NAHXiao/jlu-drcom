use drcomrs::{load_config, login_and_keep, run_interactive, Config, NetworkError, Result};
use simplelog as slog;
use std::fs::File;
use std::io;
use std::{env, thread::sleep, time::Duration};
use NetworkError::*;
fn main() -> Result<()> {
    let mut logfile: Option<String> = None;
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
            f=> {
                logfile=Some(f.to_string());
            }
        }
    }
    if let Some(path) = logfile {
        match File::create(path) {
            Ok(file) => match slog::CombinedLogger::init(vec![slog::WriteLogger::new(
                slog::LevelFilter::Info,
                slog::Config::default(),
                file,
            )]) {
                Err(e) => {
                    eprintln!("Error:{}", e);
                }
                Ok(_) => {}
            },
            Err(e) => {
                eprintln!("Error:{}", e);
            }
        }
    } else {
        slog::CombinedLogger::init(vec![slog::WriteLogger::new(
            slog::LevelFilter::Info,
            slog::Config::default(),
            io::stderr(),
        )])
        .unwrap();
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
                LoginError | LogoutError | LogoutSuccess => return Err(Box::new(e)),
                _ => {
                    log::error!("[drcom-mainloop] PANIC:{:?}", e);
                }
            },
            _ => {}
        }
        sleep(Duration::from_secs(5));
    }
}
