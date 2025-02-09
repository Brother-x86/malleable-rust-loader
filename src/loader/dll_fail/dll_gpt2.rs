use std::sync::{Arc, Mutex};
use std::thread;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;

struct ThreadManager {
    threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

impl ThreadManager {
    fn new() -> Self {
        ThreadManager {
            threads: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn spawn<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::spawn(f);
        self.threads.lock().unwrap().push(handle);
    }

    fn join_all(&self) {
        let mut threads = self.threads.lock().unwrap();
        for handle in threads.drain(..) {
            handle.join().unwrap(); // Attendre la fin des threads
        }
    }
}

fn log_message(message: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("dll_log.txt")
        .unwrap();

    writeln!(file, "{}", message).unwrap();
}

// Fonction principale de DllMain
#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: *mut std::ffi::c_void, fdw_reason: u32, lp_reserved: *mut std::ffi::c_void) -> i32 {
    match fdw_reason {
        1 => { // DLL_PROCESS_ATTACH
            log_message("DllMain start");

            // Créer un thread secondaire qui démarre plus tard
            thread::spawn(|| {
                // Faire un petit délai avant de lancer les threads (dissimulation)
                thread::sleep(Duration::from_secs(1));

                // Une fois que le thread secondaire démarre, on peut lancer les threads
                let thread_manager = Arc::new(ThreadManager::new());

                thread_manager.spawn(|| {
                    log_message("Thread 1 lancé!");
                    thread::sleep(Duration::from_secs(2)); // Simuler un travail
                    log_message("Thread 1 terminé!");
                });

                thread_manager.spawn(|| {
                    log_message("Thread 2 lancé!");
                    thread::sleep(Duration::from_secs(3)); // Simuler un travail
                    log_message("Thread 2 terminé!");
                });

                // Attendre la fin des threads
                log_message("join_all");
                thread_manager.join_all();
                log_message("Tous les threads sont terminés.");
            });

            log_message("DllMain end");
        }
        _ => {}
    }

    1 // Retourne 1 pour signaler que tout est ok
}
