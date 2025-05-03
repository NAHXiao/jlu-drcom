use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub username: String,
    pub password_md5: String,
    pub mac: String,
}
pub fn load_config() -> Result<Config, String>{}
pub fn save_config(config: &Config) -> Result<(), String>{}
/// 返回`系统推荐目录`/drcomrs/config.yaml
pub fn config_path() -> std::path::PathBuf{} 
