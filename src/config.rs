use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub file: FileConfig,
    pub interface: InterfaceConfig,
    pub suricata: SuricataConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    pub save_root_dir: String,
    #[serde(default = "default_period")]
    pub log_period: u32,
    #[serde(default = "default_period")]
    pub pcap_period: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    pub log_dir: String,
    pub rule_dir: String,
    pub rule_file_name_list: Vec<String>,
    pub config_file_path: String,
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

fn default_period() -> u32 {
    7
}

fn default_socket_path() -> String {
    "/var/run/suricata/suricata-command.socket".to_string()
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse config file")?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.file.save_root_dir.is_empty() {
            anyhow::bail!("save_root_dir is required");
        }

        if self.suricata.log_dir.is_empty() {
            anyhow::bail!("suricata.log_dir is required");
        }

        if self.suricata.rule_dir.is_empty() {
            anyhow::bail!("suricata.rule_dir is required");
        }

        if self.suricata.config_file_path.is_empty() {
            anyhow::bail!("suricata.config_file_path is required");
        }

        if self.suricata.rule_file_name_list.is_empty() {
            anyhow::bail!("suricata.rule_file_name_list is required");
        }

        Ok(())
    }
}
