use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use std::io::{self, Write};

// WinAPI imports
use winapi::shared::minwindef;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::LPVOID;
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;

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
            handle.join().unwrap(); // Bloque ici jusqu'à ce que chaque thread se termine
        }
    }
}

static mut THREAD_MANAGER: Option<ThreadManager> = None;

#[no_mangle]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;

    unsafe {
        if call_reason == DLL_PROCESS_ATTACH {
            // Crée un nouveau thread pour lancer les autres threads.
            thread::spawn(|| {
                THREAD_MANAGER = Some(ThreadManager::new());

                if let Some(manager) = &THREAD_MANAGER {
                    // Lancer les threads
                    manager.spawn(|| {
                        println!("Thread 1 clean");
                        io::stdout().flush().unwrap();
                        let sleep_time: time::Duration = time::Duration::from_millis(1000);
                        thread::sleep(sleep_time);            
                    });

                    manager.spawn(|| {
                        println!("Thread 2 clean");
                        io::stdout().flush().unwrap();
                        let sleep_time: time::Duration = time::Duration::from_millis(1000);
                        thread::sleep(sleep_time);            
                    });

                    // Attendre que tous les threads terminent
                    println!("Attente de la fin des threads...");
                    manager.join_all(); // Attend que tous les threads se terminent
                }

                println!("good job");
                io::stdout().flush().unwrap();
            });

            // Retourne immédiatement, permettant à DllMain de se terminer
            return minwindef::TRUE;
        } else if call_reason == DLL_PROCESS_DETACH {
            if let Some(manager) = &THREAD_MANAGER {
                manager.join_all(); // Assure la fin des threads avant la sortie
            }
        }
    }
    minwindef::TRUE
}
