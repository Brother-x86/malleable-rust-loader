use std::ffi::OsString;
use windows_service::{
    define_windows_service, service_dispatcher,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult},
};

// Nom du service
const SERVICE_NAME: &str = "MyRustService";

define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_args: Vec<OsString>) {
    if let Err(_e) = run_service() {
        // log erreur si besoin
    }
}

fn run_service() -> windows_service::Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Signaler au SCM que le service est en cours de démarrage
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(10),
        process_id: None,
    })?;

    // Maintenant signaler que le service est *running*
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    // Ici ta boucle principale (ton service)
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}


pub fn run_service_malleable() {
    // On démarre le service dispatcher
    let _ = service_dispatcher::start(SERVICE_NAME, ffi_service_main);
}



use std::fs::OpenOptions;
use std::io::Write;

pub fn logservice(msg: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\myrustservice.log")
    {
        let _ = writeln!(file, "{}", msg);
    }
}
