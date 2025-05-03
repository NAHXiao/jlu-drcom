pub mod config;
pub mod network;
pub mod interactive;
pub mod util;
pub use config::{Config, load_config, save_config, config_path};
pub use network::{Error as NetworkError, login_and_keep};
pub use interactive::run_interactive;
pub use util::{md5_hash, validate_mac, get_ip_by_mac};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
