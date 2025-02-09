use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE};

// Déclaration de la ressource complexe
struct ComplexResource {
    name: String,
}

impl ComplexResource {
    fn new(name: &str) -> Self {
        println!("Initialisation de ComplexResource : {}", name);
        ComplexResource {
            name: name.to_string(),
        }
    }

    fn perform_task(&self) {
        println!("Exécution de la tâche sur la ressource : {}", self.name);
    }
}

// Pour l'initialisation paresseuse, on utilise un Once pour garantir qu'elle s'exécute une seule fois
use std::sync::{Arc, Mutex, Once};
static INIT: Once = Once::new();
static mut RESOURCE: Option<Arc<Mutex<ComplexResource>>> = None;

// Fonction d'initialisation paresseuse
fn initialize_resource() {
    INIT.call_once(|| {
        let resource = ComplexResource::new("Resource1");
        unsafe {
            RESOURCE = Some(Arc::new(Mutex::new(resource)));
        }
        println!("Ressource initialisée avec succès!");
    });
}

// Fonction qui démarre un thread pour effectuer une tâche après DllMain
fn run_in_thread() {
    std::thread::spawn(move || {
        // Initialisation paresseuse dans un thread séparé
        initialize_resource();

        // Simuler un travail effectué après l'initialisation
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Accéder et utiliser la ressource
        unsafe {
            if let Some(resource) = &RESOURCE {
                let resource = resource.lock().unwrap();
                resource.perform_task();
            }
        }
    });
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;
    const DLL_THREAD_ATTACH: DWORD = 2;
    const DLL_THREAD_DETACH: DWORD = 3;

    unsafe {
        // Désactive la gestion des appels de threads supplémentaires
        DisableThreadLibraryCalls(dll_module);
    }

    if call_reason == DLL_PROCESS_ATTACH {
        println!("DLL_PROCESS_ATTACH");
        // Initialisation paresseuse dans un thread
        run_in_thread();
    } else if call_reason == DLL_PROCESS_DETACH {
        println!("DLL_PROCESS_DETACH");
    } else if call_reason == DLL_THREAD_ATTACH {
        println!("DLL_THREAD_ATTACH");
    } else if call_reason == DLL_THREAD_DETACH {
        println!("DLL_THREAD_DETACH");
    } else {
        println!("Valeur inconnue");
    };

    BOOL::TRUE
}
