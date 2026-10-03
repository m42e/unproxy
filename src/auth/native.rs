use anyhow::{Context as _, Result, anyhow};

/// Stateful native SPNEGO exchange. The dynamic library is retained with the context.
#[cfg(all(feature = "negotiate", unix))]
pub struct NegotiateContext {
    lib: libloading::Library,
    ctx: *mut std::ffi::c_void,
    target: *mut std::ffi::c_void,
    host: String,
}
#[cfg(all(feature = "negotiate", unix))]
#[repr(C)]
struct GssBuf {
    len: usize,
    value: *mut std::ffi::c_void,
}
#[cfg(all(feature = "negotiate", unix))]
#[repr(C)]
struct GssOid {
    len: u32,
    elements: *mut std::ffi::c_void,
}
#[cfg(all(feature = "negotiate", unix))]
type GssStatus = i32;
#[cfg(all(feature = "negotiate", unix))]
type GssImportName = unsafe extern "C" fn(
    *mut u32,
    *mut GssBuf,
    *mut GssOid,
    *mut *mut std::ffi::c_void,
) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssInitSecContext = unsafe extern "C" fn(
    *mut u32,
    *mut std::ffi::c_void,
    *mut *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *mut GssOid,
    u32,
    u32,
    *mut std::ffi::c_void,
    *mut GssBuf,
    *mut *mut GssOid,
    *mut GssBuf,
    *mut u32,
    *mut u32,
) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssReleaseBuffer = unsafe extern "C" fn(*mut u32, *mut GssBuf) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssDeleteContext =
    unsafe extern "C" fn(*mut u32, *mut *mut std::ffi::c_void, *mut GssBuf) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssReleaseName = unsafe extern "C" fn(*mut u32, *mut *mut std::ffi::c_void) -> GssStatus;

#[cfg(all(feature = "negotiate", unix))]
unsafe fn import_gss_target(
    host: &str,
    import: GssImportName,
    release_name: Option<GssReleaseName>,
    mut display_status: impl FnMut(u32, i32) -> String,
) -> Result<*mut std::ffi::c_void> {
    let target = format!("HTTP@{host}");
    let mut name = GssBuf {
        len: target.len(),
        value: target.as_ptr() as *mut _,
    };
    // Host-based service name OID 1.2.840.113554.1.2.1.4.
    let mut name_oid_bytes: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
    let mut name_oid = GssOid {
        len: 10,
        elements: name_oid_bytes.as_mut_ptr().cast(),
    };
    let mut minor = 0;
    let mut imported = std::ptr::null_mut();
    let status = unsafe { import(&mut minor, &mut name, &mut name_oid, &mut imported) };
    if status != 0 {
        let major_text = display_status(status as u32, 1);
        let minor_text = display_status(minor, 2);
        // Some implementations can return a handle alongside an error. Release it
        // before returning so a failed initialization does not leak the native name.
        if !imported.is_null()
            && let Some(release) = release_name
        {
            let mut release_minor = 0;
            unsafe { release(&mut release_minor, &mut imported) };
        }
        return Err(anyhow!(
            "GSSAPI name import failed for HTTP@{host}: major={status} ({major_text}), minor={minor} ({minor_text})"
        ));
    }
    Ok(imported)
}

#[cfg(all(feature = "negotiate", unix))]
unsafe fn release_gss_handles(
    ctx: &mut *mut std::ffi::c_void,
    target: &mut *mut std::ffi::c_void,
    delete_context: Option<GssDeleteContext>,
    release_buffer: Option<GssReleaseBuffer>,
    release_name: Option<GssReleaseName>,
) {
    if !ctx.is_null()
        && let Some(delete) = delete_context
    {
        let mut minor = 0;
        let mut output = GssBuf {
            len: 0,
            value: std::ptr::null_mut(),
        };
        unsafe { delete(&mut minor, ctx, &mut output) };
        if !output.value.is_null()
            && let Some(release) = release_buffer
        {
            unsafe { release(&mut minor, &mut output) };
        }
    }
    if !target.is_null()
        && let Some(release) = release_name
    {
        let mut minor = 0;
        unsafe { release(&mut minor, target) };
    }
}

#[cfg(all(feature = "negotiate", unix))]
impl NegotiateContext {
    pub fn new(host: &str) -> Result<Self> {
        unsafe {
            let names: [&str; 5] = [
                "libgssapi_krb5.so.2",
                "libgssapi.so.3",
                "libgssapi_krb5.dylib",
                "/System/Library/Frameworks/GSS.framework/GSS",
                "libgssapi.dylib",
            ];
            let lib = names
                .iter()
                .find_map(|n| libloading::Library::new(n).ok())
                .ok_or_else(|| anyhow!("GSSAPI library is unavailable"))?;
            let import: libloading::Symbol<GssImportName> = lib.get(b"gss_import_name\0")?;
            let release_name = lib
                .get::<GssReleaseName>(b"gss_release_name\0")
                .ok()
                .map(|symbol| *symbol);
            let target = import_gss_target(host, *import, release_name, |status, kind| {
                gss_status_text(&lib, status, kind)
            })?;
            Ok(Self {
                lib,
                ctx: std::ptr::null_mut(),
                target,
                host: host.to_owned(),
            })
        }
    }
    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        unsafe {
            let f: libloading::Symbol<GssInitSecContext> = self
                .lib
                .get(b"gss_init_sec_context\0")
                .context(format!("loading GSSAPI context step for {}", self.host))?;
            let mut input = GssBuf {
                len: server_token.map_or(0, |v| v.len()),
                value: server_token.map_or(std::ptr::null_mut::<std::ffi::c_void>(), |v| {
                    v.as_ptr() as *mut std::ffi::c_void
                }),
            };
            let mut out = GssBuf {
                len: 0,
                value: std::ptr::null_mut(),
            };
            let mut mech_bytes: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
            let mut mech = GssOid {
                len: 6,
                elements: mech_bytes.as_mut_ptr().cast(),
            };
            let mut flags = 0;
            let mut minor = 0;
            // GSS_C_NO_CREDENTIAL = NULL, mutual-auth flag = 2.
            let status = f(
                &mut minor,
                std::ptr::null_mut(),
                &mut self.ctx,
                self.target,
                &mut mech,
                2,
                0,
                std::ptr::null_mut(),
                &mut input,
                std::ptr::null_mut(),
                &mut out,
                &mut flags,
                std::ptr::null_mut(),
            );
            let error = (status as u32 & 0xffff_0000) != 0;
            let bytes = if out.len == 0 {
                None
            } else {
                Some(std::slice::from_raw_parts(out.value as *const u8, out.len).to_vec())
            };
            release_gss_buffer(&self.lib, &mut minor, &mut out);
            if error {
                return Err(anyhow!(
                    "Negotiate token step for {} failed: major={} ({}), minor={} ({})",
                    self.host,
                    status,
                    gss_status_text(&self.lib, status as u32, 1),
                    minor,
                    gss_status_text(&self.lib, minor, 2)
                ));
            }
            Ok(bytes)
        }
    }
}
#[cfg(all(feature = "negotiate", unix))]
unsafe fn release_gss_buffer(lib: &libloading::Library, minor: &mut u32, buf: &mut GssBuf) {
    if !buf.value.is_null()
        && let Ok(f) = unsafe { lib.get::<GssReleaseBuffer>(b"gss_release_buffer\0") }
    {
        unsafe {
            f(minor, buf);
        }
    }
}
#[cfg(all(feature = "negotiate", unix))]
fn gss_status_text(lib: &libloading::Library, value: u32, kind: i32) -> String {
    unsafe {
        let Ok(f) = lib.get::<unsafe extern "C" fn(
            *mut u32,
            u32,
            i32,
            *mut GssOid,
            *mut u32,
            *mut GssBuf,
        ) -> GssStatus>(b"gss_display_status\0") else {
            return "status text unavailable".into();
        };
        let (mut ctx, mut texts) = (0u32, Vec::new());
        loop {
            let (mut minor, mut buf) = (
                0u32,
                GssBuf {
                    len: 0,
                    value: std::ptr::null_mut(),
                },
            );
            let result = f(
                &mut minor,
                value,
                kind,
                std::ptr::null_mut(),
                &mut ctx,
                &mut buf,
            );
            if result != 0 || buf.value.is_null() {
                break;
            }
            texts.push(
                String::from_utf8_lossy(std::slice::from_raw_parts(
                    buf.value as *const u8,
                    buf.len,
                ))
                .into_owned(),
            );
            release_gss_buffer(lib, &mut minor, &mut buf);
            if ctx == 0 || texts.len() > 8 {
                break;
            }
        }
        if texts.is_empty() {
            "status text unavailable".into()
        } else {
            texts.join("; ")
        }
    }
}
#[cfg(all(feature = "negotiate", unix))]
impl Drop for NegotiateContext {
    fn drop(&mut self) {
        unsafe {
            let delete_context = self
                .lib
                .get::<GssDeleteContext>(b"gss_delete_sec_context\0")
                .ok()
                .map(|symbol| *symbol);
            let release_buffer = self
                .lib
                .get::<GssReleaseBuffer>(b"gss_release_buffer\0")
                .ok()
                .map(|symbol| *symbol);
            let release_name = self
                .lib
                .get::<GssReleaseName>(b"gss_release_name\0")
                .ok()
                .map(|symbol| *symbol);
            release_gss_handles(
                &mut self.ctx,
                &mut self.target,
                delete_context,
                release_buffer,
                release_name,
            );
        }
    }
}
#[cfg(all(feature = "negotiate", not(unix), not(windows)))]
impl NegotiateContext {
    pub fn new(_: &str) -> Result<Self> {
        Err(anyhow!("native Negotiate unavailable on this platform"))
    }
    pub fn step(&mut self, _: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        Err(anyhow!("native Negotiate unavailable"))
    }
}
#[cfg(all(feature = "negotiate", windows))]
#[derive(Clone, Copy)]
#[repr(C)]
struct SecHandle {
    a: usize,
    b: usize,
}
#[cfg(all(feature = "negotiate", windows))]
#[repr(C)]
struct SecBuffer {
    size: u32,
    kind: u32,
    data: *mut std::ffi::c_void,
}
#[cfg(all(feature = "negotiate", windows))]
#[repr(C)]
struct SecBufferDesc {
    version: u32,
    count: u32,
    buffers: *mut SecBuffer,
}
#[cfg(all(feature = "negotiate", windows))]
type InitializeSecurityContextW = unsafe extern "system" fn(
    *mut SecHandle,
    *mut SecHandle,
    *const u16,
    u32,
    u32,
    u32,
    *mut SecBufferDesc,
    u32,
    *mut SecHandle,
    *mut SecBufferDesc,
    *mut u32,
    *mut i64,
) -> i32;
#[cfg(all(feature = "negotiate", windows))]
type SspiHandleAction = unsafe extern "system" fn(*mut SecHandle) -> i32;
#[cfg(all(feature = "negotiate", windows))]
pub struct NegotiateContext {
    lib: libloading::Library,
    cred: SecHandle,
    ctx: SecHandle,
    target: Vec<u16>,
}
#[cfg(all(feature = "negotiate", windows))]
impl NegotiateContext {
    pub fn new(host: &str) -> Result<Self> {
        unsafe {
            let lib = libloading::Library::new("secur32.dll").context("loading Windows SSPI")?;
            let acquire: libloading::Symbol<
                unsafe extern "system" fn(
                    *const u16,
                    *const u16,
                    u32,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *mut SecHandle,
                    *mut i64,
                ) -> i32,
            > = lib.get(b"AcquireCredentialsHandleW\0")?;
            let mut cred = SecHandle { a: 0, b: 0 };
            let package = "Negotiate"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let status = acquire(
                std::ptr::null(),
                package.as_ptr(),
                2,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut cred,
                std::ptr::null_mut(),
            );
            if status < 0 {
                return Err(anyhow!(
                    "AcquireCredentialsHandleW failed: 0x{:08x}",
                    status as u32
                ));
            }
            Ok(Self {
                lib,
                cred,
                ctx: SecHandle { a: 0, b: 0 },
                target: format!("HTTP/{host}")
                    .encode_utf16()
                    .chain(Some(0))
                    .collect(),
            })
        }
    }
    pub fn step(&mut self, _server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        unsafe {
            let init: libloading::Symbol<InitializeSecurityContextW> =
                self.lib.get(b"InitializeSecurityContextW\0")?;
            let _ = _server_token; // The Windows adapter intentionally ignores server challenge tokens.
            let in_desc: *mut SecBufferDesc = std::ptr::null_mut();
            let mut prior = self.ctx;
            let prior_ptr = if prior.a == 0 && prior.b == 0 {
                std::ptr::null_mut()
            } else {
                &mut prior as *mut _
            };
            let mut next = SecHandle { a: 0, b: 0 };
            let mut storage = vec![0u8; 65536];
            let mut outbuf = SecBuffer {
                size: storage.len() as u32,
                kind: 2,
                data: storage.as_mut_ptr() as *mut _,
            };
            let mut outdesc = SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut outbuf,
            };
            let mut attrs = 0;
            let status = init(
                &mut self.cred,
                prior_ptr,
                self.target.as_ptr(),
                2,
                0,
                0,
                in_desc,
                0,
                &mut next,
                &mut outdesc,
                &mut attrs,
                std::ptr::null_mut(),
            );
            if status < 0 {
                return Err(anyhow!(
                    "InitializeSecurityContextW failed: 0x{:08x}",
                    status as u32
                ));
            }
            self.ctx = next;
            storage.truncate(outbuf.size as usize);
            Ok((!storage.is_empty()).then_some(storage))
        }
    }
}

#[cfg(all(feature = "negotiate", windows))]
impl Drop for NegotiateContext {
    fn drop(&mut self) {
        unsafe {
            if (self.ctx.a != 0 || self.ctx.b != 0)
                && let Ok(f) = self.lib.get::<SspiHandleAction>(b"DeleteSecurityContext\0")
            {
                f(&mut self.ctx);
            }
            if (self.cred.a != 0 || self.cred.b != 0)
                && let Ok(f) = self.lib.get::<SspiHandleAction>(b"FreeCredentialsHandle\0")
            {
                f(&mut self.cred);
            }
        }
    }
}

#[cfg(feature = "negotiate")]
pub(super) fn initial_token(host: &str) -> Result<Option<Vec<u8>>> {
    let mut context = NegotiateContext::new(host)
        .with_context(|| format!("initializing Negotiate for upstream {host}"))?;
    context
        .step(None)
        .with_context(|| format!("generating Negotiate token for upstream {host}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RELEASED_NAMES: AtomicUsize = AtomicUsize::new(0);
    static DELETED_CONTEXTS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_BUFFERS: AtomicUsize = AtomicUsize::new(0);
    static IMPORT_NAME_MATCHES: AtomicUsize = AtomicUsize::new(0);
    static IMPORT_OID_MATCHES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fixture_import_failure(
        minor: *mut u32,
        name: *mut GssBuf,
        oid: *mut GssOid,
        output: *mut *mut std::ffi::c_void,
    ) -> GssStatus {
        let bytes = unsafe { std::slice::from_raw_parts((*name).value.cast::<u8>(), (*name).len) };
        if bytes == b"HTTP@fixture.test" {
            IMPORT_NAME_MATCHES.fetch_add(1, Ordering::SeqCst);
        }
        let oid_bytes = unsafe {
            std::slice::from_raw_parts((*oid).elements.cast::<u8>(), (*oid).len as usize)
        };
        if oid_bytes == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04] {
            IMPORT_OID_MATCHES.fetch_add(1, Ordering::SeqCst);
        }
        unsafe {
            *minor = 17;
            *output = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
        }
        0x0001_0000
    }

    unsafe extern "C" fn fixture_release_name(
        _: *mut u32,
        name: *mut *mut std::ffi::c_void,
    ) -> GssStatus {
        RELEASED_NAMES.fetch_add(1, Ordering::SeqCst);
        unsafe { *name = std::ptr::null_mut() };
        0
    }

    unsafe extern "C" fn fixture_delete_context(
        _: *mut u32,
        context: *mut *mut std::ffi::c_void,
        output: *mut GssBuf,
    ) -> GssStatus {
        DELETED_CONTEXTS.fetch_add(1, Ordering::SeqCst);
        unsafe {
            *context = std::ptr::null_mut();
            (*output).len = 0;
            (*output).value = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
        }
        0x0001_0000
    }

    unsafe extern "C" fn fixture_release_buffer(_: *mut u32, buffer: *mut GssBuf) -> GssStatus {
        RELEASED_BUFFERS.fetch_add(1, Ordering::SeqCst);
        unsafe { (*buffer).value = std::ptr::null_mut() };
        0
    }

    #[test]
    fn failed_gss_name_import_releases_a_returned_handle() {
        let _guard = TEST_LOCK.lock().unwrap();
        RELEASED_NAMES.store(0, Ordering::SeqCst);
        IMPORT_NAME_MATCHES.store(0, Ordering::SeqCst);
        IMPORT_OID_MATCHES.store(0, Ordering::SeqCst);
        let error = unsafe {
            import_gss_target(
                "fixture.test",
                fixture_import_failure,
                Some(fixture_release_name),
                |status, kind| format!("status {status} kind {kind}"),
            )
        }
        .unwrap_err();

        assert!(error.to_string().contains("HTTP@fixture.test"));
        assert!(error.to_string().contains("status 65536 kind 1"));
        assert!(error.to_string().contains("status 17 kind 2"));
        assert_eq!(IMPORT_NAME_MATCHES.load(Ordering::SeqCst), 1);
        assert_eq!(IMPORT_OID_MATCHES.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_NAMES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn gss_drop_releases_context_output_and_name_once() {
        let _guard = TEST_LOCK.lock().unwrap();
        RELEASED_NAMES.store(0, Ordering::SeqCst);
        DELETED_CONTEXTS.store(0, Ordering::SeqCst);
        RELEASED_BUFFERS.store(0, Ordering::SeqCst);
        let mut context = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
        let mut target = std::ptr::NonNull::<u16>::dangling().as_ptr().cast();

        unsafe {
            release_gss_handles(
                &mut context,
                &mut target,
                Some(fixture_delete_context),
                Some(fixture_release_buffer),
                Some(fixture_release_name),
            );
            release_gss_handles(
                &mut context,
                &mut target,
                Some(fixture_delete_context),
                Some(fixture_release_buffer),
                Some(fixture_release_name),
            );
        }

        assert!(context.is_null());
        assert!(target.is_null());
        assert_eq!(DELETED_CONTEXTS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_BUFFERS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_NAMES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_gss_context_step_is_a_best_effort_smoke_test() {
        let mut context = match NegotiateContext::new("localhost") {
            Ok(c) => c,
            Err(e) if e.to_string().contains("GSSAPI library is unavailable") => return,
            Err(e) => panic!("GSSAPI name import failed: {e:#}"),
        };
        match context.step(None) {
            Ok(None) => {}
            Ok(Some(token)) => assert!(!token.is_empty()),
            Err(e) => assert!(e.to_string().contains("localhost"), "{e:#}"),
        }
    }

    #[test]
    #[ignore = "requires a configured native GSS identity or ticket cache"]
    fn native_gss_context_step_uses_host_based_spnego() {
        let mut context = NegotiateContext::new("localhost").unwrap();
        let token = context.step(None).unwrap().expect("initial SPNEGO token");
        assert!(!token.is_empty());
    }
}
