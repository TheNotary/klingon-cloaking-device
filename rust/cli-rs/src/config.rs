use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct KcdConfig {
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub knock_password: String,
    pub access_password: String,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knock_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knock_chunks: Option<u8>,
}

pub fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    Ok(home.join(".kcd").join("config"))
}

pub fn load_config() -> Result<Option<KcdConfig>, Box<dyn std::error::Error>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)?;
    let config: KcdConfig = serde_yml::from_str(&contents)?;
    Ok(Some(config))
}

pub fn save_config(config: &KcdConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let yaml = serde_yml::to_string(config)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&path)?;
    file.write_all(yaml.as_bytes())?;
    Ok(())
}
