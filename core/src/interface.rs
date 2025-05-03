use anyhow::Result;
use colored::Colorize;
use pcap::Device;

/// Represents a network interface
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
}

/// Lists all available network interfaces
pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    let devices = Device::list()?;
    Ok(devices
        .into_iter()
        .map(|device| NetworkInterface {
            name: device.name,
            description: device.desc,
        })
        .collect())
}

/// Formats interface list for display
pub fn format_interface_list(interfaces: &[NetworkInterface]) -> String {
    let mut output = String::new();
    output.push_str(&"Available interfaces:\n".bold().underline().to_string());
    
    for interface in interfaces {
        if let Some(desc) = &interface.description {
            output.push_str(&format!(
                "{} -> {}\n",
                interface.name.bold().green(),
                desc
            ));
        } else {
            output.push_str(&format!("{}\n", interface.name.bold().green()));
        }
    }
    
    output
}

/// Validates if an interface exists
pub fn validate_interface(interface_name: &str) -> Result<bool> {
    let interfaces = list_interfaces()?;
    Ok(interfaces.iter().any(|i| i.name == interface_name))
} 