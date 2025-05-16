// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use anansi_core::AnansiFacade;

#[tauri::command]
async fn get_interfaces() -> Result<Vec<String>, String> {
    let facade = AnansiFacade::new(false);
    facade.list_interfaces()
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_interfaces])
        .run(tauri::generate_context!())
        .expect("Error while running tauri application!");
}
