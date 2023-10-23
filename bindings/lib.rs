use std::{ffi::c_char, io::Error};

use windows_sys::{
    s, w,
    Win32::{
        Foundation::HMODULE,
        System::LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryW},
    },
};

#[repr(C)]
pub struct SeResult {
    pub os_error: u32,
    pub se_error: *const c_char,
}

impl std::fmt::Debug for SeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeResult")
            .field("os_error", &self.os_error)
            .field("se_error", unsafe {
                &std::ffi::CStr::from_ptr(self.se_error)
            })
            .finish()
    }
}

impl std::fmt::Display for SeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let io = Error::from_raw_os_error(self.os_error as i32);
        let cstr = unsafe { std::ffi::CStr::from_ptr(self.se_error) };
        if let Ok(s) = cstr.to_str() {
            write!(f, "{s} {io}")
        } else {
            write!(f, "Rust format error {io}")
        }
    }
}

impl std::error::Error for SeResult {}

pub type PfnSeSetEnvironmentVariable =
    extern "C" fn(name: *const u16, name_size: u32, value: *const u16, value_size: u32) -> SeResult;

pub type PFNseWarningCallBack = extern "C" fn(SeResult);

pub type PfnSeSetWarningCallback =
    extern "C" fn(PFNseWarningCallBack) -> Option<PFNseWarningCallBack>;

pub struct SetEnv {
    _library: Library,
    set_env: PfnSeSetEnvironmentVariable,
}

impl SetEnv {
    pub fn new() -> Result<SetEnv, Error> {
        unsafe {
            let lib = LoadLibraryW(w!("setenv.dll"));
            if lib == 0 {
                return Err(Error::last_os_error());
            }
            let library = Library(lib);

            let pfn = GetProcAddress(library.0, s!("seSetParentProcessEnvironmentVariable"));
            if pfn.is_none() {
                return Err(Error::last_os_error());
            }

            Ok(Self {
                _library: library,
                set_env: std::mem::transmute(pfn),
            })
        }
    }

    pub fn set_parent_var(&self, name: &str, value: &str) -> Result<(), SeResult> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let value: Vec<u16> = value.encode_utf16().collect();

        let result = (self.set_env)(
            name.as_ptr(),
            name.len() as _,
            value.as_ptr(),
            value.len() as _,
        );

        if result.os_error != 0 || !result.se_error.is_null() {
            Err(result)
        } else {
            Ok(())
        }
    }
}

struct Library(HMODULE);

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}
