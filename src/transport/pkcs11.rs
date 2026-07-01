// SPDX-License-Identifier: GPL-3.0-or-later
//! PKCS#11 certificate/key loading via the OpenSSL `pkcs11` engine.
//!
//! Only compiled with the `pkcs11` cargo feature. Both the private key (which
//! stays on the token) and, optionally, the certificate can be loaded from a
//! `pkcs11:` URI.
//!
//! The OpenSSL `ENGINE_*` API is deprecated in OpenSSL 3.x and not bound by
//! `openssl-sys`, so we declare the handful of functions we need ourselves and
//! link against `libcrypto` directly. Requires the system OpenSSL `pkcs11`
//! engine (e.g. `libengine-pkcs11-openssl`) plus a PKCS#11 module such as
//! OpenSC, discoverable via `ENGINE_by_id("pkcs11")`.

use anyhow::{Result, bail};
use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use openssl_sys::{EVP_PKEY, X509 as FfiX509};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long, c_void};

// Opaque OpenSSL handles (names mirror the C API).
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
type ENGINE = c_void;
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
type UI_METHOD = c_void;

/// Parameter struct for the libp11 `LOAD_CERT_CTRL` engine command.
#[repr(C)]
struct LoadCertParams {
    s_slot_cert_id: *const c_char,
    cert: *mut FfiX509,
}

unsafe extern "C" {
    fn ENGINE_load_builtin_engines();
    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    fn ENGINE_init(e: *mut ENGINE) -> c_int;
    fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_load_private_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        i: c_long,
        p: *mut c_void,
        f: Option<extern "C" fn()>,
        cmd_optional: c_int,
    ) -> c_int;
}

/// Initialize the `pkcs11` engine, run `f`, then finish and free it.
fn with_engine<T>(f: impl FnOnce(*mut ENGINE) -> Result<T>) -> Result<T> {
    let engine_id = CString::new("pkcs11").unwrap();
    unsafe {
        ENGINE_load_builtin_engines();
        let engine = ENGINE_by_id(engine_id.as_ptr());
        if engine.is_null() {
            bail!(
                "OpenSSL 'pkcs11' engine not found. Install libengine-pkcs11-openssl \
                 and a PKCS#11 module (e.g. OpenSC)."
            );
        }
        if ENGINE_init(engine) == 0 {
            ENGINE_free(engine);
            bail!("failed to initialize the pkcs11 engine");
        }
        let result = f(engine);
        ENGINE_finish(engine);
        ENGINE_free(engine);
        result
    }
}

/// Load a private key identified by a `pkcs11:` URI from the token.
pub fn load_private_key(uri: &str) -> Result<PKey<Private>> {
    let key_id = CString::new(uri)?;
    with_engine(|engine| unsafe {
        let pkey = ENGINE_load_private_key(
            engine,
            key_id.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if pkey.is_null() {
            bail!("pkcs11 engine could not load key for URI: {}", uri);
        }
        Ok(PKey::from_ptr(pkey))
    })
}

/// Load a certificate identified by a `pkcs11:` URI from the token.
pub fn load_certificate(uri: &str) -> Result<X509> {
    let cert_id = CString::new(uri)?;
    let cmd = CString::new("LOAD_CERT_CTRL").unwrap();
    with_engine(|engine| unsafe {
        let mut params = LoadCertParams {
            s_slot_cert_id: cert_id.as_ptr(),
            cert: std::ptr::null_mut(),
        };
        let rc = ENGINE_ctrl_cmd(
            engine,
            cmd.as_ptr(),
            0,
            &mut params as *mut LoadCertParams as *mut c_void,
            None,
            1,
        );
        if rc == 0 || params.cert.is_null() {
            bail!("pkcs11 engine could not load certificate for URI: {}", uri);
        }
        Ok(X509::from_ptr(params.cert))
    })
}
