use winapi::um::tlhelp32;
use winapi::um::winnt;
use winapi::um::winbase;
use winapi::um::errhandlingapi;
use winapi::um::processthreadsapi;
use winapi::um::fileapi;
use winapi::um::handleapi;
use winapi::um::libloaderapi;
use winapi::um::memoryapi;
use winapi::shared::ntdef;
use winapi::shared::minwindef;
use std::ptr;
use std::ffi;

#[derive(Debug)]
pub enum Error {
    ProcessHandleError(&'static str),
    InjectionError(&'static str),
    ProcessNotFound,
    UnknownError,
}

pub enum ProcessQuery<'a> {
    ProcId(u32),
    ProcName(&'a str),
}

unsafe fn get_process_handle(query: ProcessQuery) -> Result<winnt::HANDLE, Error> {
    // Create a snapshot of running processes
    let snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0);
    if snapshot == handleapi::INVALID_HANDLE_VALUE {
        return Err(Error::ProcessHandleError("failed to create process snapshot"))
    }

    let mut process_entry = tlhelp32::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<tlhelp32::PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    // Get handles to those that match the query
    let mut found_process = tlhelp32::Process32First(snapshot, &mut process_entry as *mut tlhelp32::PROCESSENTRY32);
    while found_process != 0 {
        let does_match_query = match query {
            ProcessQuery::ProcId(pid) => {
                process_entry.th32ProcessID == pid
            }
            ProcessQuery::ProcName(process_name) => {
                let procname_str: String = process_entry.szExeFile.iter()
                    .map(|i| (*i as u8) as char)
                    .take_while(|c| *c != '\0')
                    .collect();
                procname_str == process_name
            }
        };
        if does_match_query {
            let proc_access =  winnt::PROCESS_CREATE_THREAD 
                             | winnt::PROCESS_VM_OPERATION
                             | winnt::PROCESS_VM_READ
                             | winnt::PROCESS_VM_WRITE
                             | winnt::PROCESS_QUERY_INFORMATION;
            let process_handle = processthreadsapi::OpenProcess(proc_access, 0, process_entry.th32ProcessID);
            if process_handle == ntdef::NULL {
                return Err(Error::ProcessHandleError("failed to open process handle")); 
            }
            return Ok(process_handle);
        }

        found_process = tlhelp32::Process32Next(snapshot, &mut process_entry as *mut tlhelp32::PROCESSENTRY32);
    }
    
    Err(Error::ProcessNotFound)
}

unsafe fn inject_dll(process_handle: winnt::HANDLE, dll_file: &str) -> Result<(), Error> {
    if process_handle == ntdef::NULL {
        return Err(Error::ProcessHandleError("attempting to inject into non-existant process")); 
    }

    // Get the fill path for the DLL
    let dll_path_buf: [i8; minwindef::MAX_PATH] = [0; minwindef::MAX_PATH];
    let dll_path = std::mem::transmute(&dll_path_buf);
    let dll_file_c = match ffi::CString::new(dll_file) {
        Ok(cs) => cs,
        Err(_) => {
            handleapi::CloseHandle(process_handle);
            return Err(Error::InjectionError("failed to convert dll filename to C string"));
        }
    };
    let length = fileapi::GetFullPathNameA(dll_file_c.into_raw(), minwindef::MAX_PATH as u32, dll_path, ptr::null_mut());
    if length == 0 {
        handleapi::CloseHandle(process_handle);
        return Err(Error::InjectionError("failed to get dll path"));
    } else if length > minwindef::MAX_PATH as u32 {
        handleapi::CloseHandle(process_handle);
        return Err(Error::InjectionError("dll path is too long"));
    }

    let dll_path_len = winbase::lstrlenA(dll_path) as usize;

    // Get the address of the LoadLibraryA method
    let loadlibrary_addr = libloaderapi::GetProcAddress(libloaderapi::GetModuleHandleA(ffi::CString::new("kernel32.dll").unwrap().as_ptr()), 
                                                        ffi::CString::new("LoadLibraryA").unwrap().as_ptr());
    let loadlibrary_addr = std::mem::transmute(loadlibrary_addr);
    
    // Allocate memory in the process for the DLL path and write it
    let remote_mem = memoryapi::VirtualAllocEx(process_handle, ptr::null_mut(), dll_path_len + 1, 
                                               winnt::MEM_RESERVE | winnt::MEM_COMMIT, winnt::PAGE_READWRITE);
    if remote_mem.is_null() {
        handleapi::CloseHandle(process_handle);
        return Err(Error::InjectionError("failed to allocate memory in remote process"));
    }
    let write_ok = memoryapi::WriteProcessMemory(process_handle, remote_mem, dll_path as *mut ffi::c_void, dll_path_len + 1, ptr::null_mut());
    if write_ok == 0 {
        handleapi::CloseHandle(process_handle);
        let err_code = errhandlingapi::GetLastError();
        println!("ERROR CODE: {}", err_code);
        return Err(Error::InjectionError("failed to write memory in remote process"));
    }

    // Cause the process to load the DLL by starting a thread to run LoadLibraryA
    let loadlibrary_addr_option = Some(loadlibrary_addr);
    let remote_thread = processthreadsapi::CreateRemoteThread(process_handle, ptr::null_mut(), 0, loadlibrary_addr_option, remote_mem, 0, ptr::null_mut());
    if remote_thread.is_null() {
        handleapi::CloseHandle(process_handle);
        return Err(Error::InjectionError("failed to create remote thread")); 
    }

    handleapi::CloseHandle(process_handle);
    Ok(())
}

pub fn perform_injection(query: ProcessQuery, dll_file: &str) -> Result<(), Error> {
    unsafe {
        let handle = get_process_handle(query)?;
        inject_dll(handle, dll_file)?;
    }
    Ok(())
}