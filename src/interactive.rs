use crate::config::{config_path, save_config, Config};
use crate::util::{encrypt, fingerprint};
use mac_address::MacAddress;
use rpassword::read_password;
use std::io::{self, Write};
use std::str::FromStr;
pub fn run_interactive() -> crate::Result<Config> {
    let username = prompt_input("Username: ")?;
    print!("Password (hidden): ");
    io::stdout().flush()?;
    let password = read_password()?;

    let mut mac=[0;6];
    loop {
        let _mac = prompt_input("MAC Address XXXXXXXXXXXX/XX:XX:XX:XX:XX:XX:")?;
        if let Ok(m) = MacAddress::from_str(&_mac) {
            mac = m.bytes();
            break;
        } else {
            println!("Invalid MAC address format");
        }
    }
    let config = Config::new(username, encrypt(&password, &fingerprint()), mac);
    print!("Save this config? (Y/n): ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    if answer.trim().is_empty() || answer.trim().to_lowercase().starts_with('y') {
        if config_path().exists() {
            println!("Config file already exists at: {}", config_path().display());
            print!("Overwrite? (y/N): ");
            io::stdout().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;

            if !answer.trim().to_lowercase().starts_with('y') {
                print!("Config");
                return Ok(config);
            }
        }
        save_config(&config)?;
        println!("Config saved to: {}", config_path().display());
    }
    Ok(config)
}

fn prompt_input(message: &str) -> io::Result<String> {
    print!("{}", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}
