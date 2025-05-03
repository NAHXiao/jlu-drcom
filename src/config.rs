use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub username: String,
    pub password_enctypted: String,
    pub mac: String,//TODO:
    #[serde(default = "default_server_addr")]
    pub server_addr: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_os_name")]
    pub os_name: String,
}

fn default_server_addr() -> String {
    "10.100.61.3".to_string()
}

fn default_server_port() -> u16 {
    61440
}

fn default_hostname() -> String {
    "drcom".to_string()
}

fn default_os_name() -> String {
    "drcom".to_string()
}

impl Config {
    pub fn new(username: String, password: String, mac: String) -> Self {//TODO:
        Config {
            username,
            password_enctypted: password,
            mac,
            server_addr: default_server_addr(),
            server_port: default_server_port(),
            hostname: default_hostname(),
            os_name: default_os_name(),
        }
    }
}

pub fn load_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Err("Configuration file does not exist".into());
    }

    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let config: Config = serde_yaml::from_str(&contents)?;
    Ok(config)
}
pub fn save_config(config: &Config) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(config)?;
    let mut file = File::create(&path)?;
    file.write_all(content.as_bytes())?;

    Ok(())
}
pub fn config_path() -> PathBuf {
    let config_dir = if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("drcomrs")
    } else {
        PathBuf::from(".")
    };

    config_dir.join("config.yaml")
}
