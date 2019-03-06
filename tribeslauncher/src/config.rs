use std::fs;
use serde::{Serialize, Deserialize};
use serde_yaml;

#[derive(Serialize, Deserialize, Debug)]
pub enum LoginServer {
    HiRez,
    TAServer,
    Custom {ip: String},
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InjectionMode {
    Manual,
    Auto(i32),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ReleaseChannel {
    Stable,
    Beta,
    Edge
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub game_path: String,
    pub dll_path: String,
    
    pub login_server: LoginServer,

    pub injection_mode: InjectionMode,

    pub dll_release: ReleaseChannel,
}

impl Config {

    fn new(filename: &str) -> Result<Config, &'static str> {
        let file_contents = fs::read_to_string(filename).or(Err("failed to read file"))?;
        serde_yaml::from_str(&file_contents).or(Err("failed to deserialize"))
    }

    fn save(&self, filename: &str) -> Result<(), &'static str> {
      let serialized = serde_yaml::to_string(self).or(Err("failed to serialize"))?;
      fs::write(filename, serialized).or(Err("failed to write file"))
    }

}