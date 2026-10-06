use anyhow::{Context as _, Result, anyhow};

/// Stateful native SPNEGO exchange. The dynamic library is retained with the context.
#[cfg(all(feature = "negotiate", unix))]
pub struct NegotiateContext {
    lib: libloading::Library,
    ctx: *mut std::ffi::c_void,
    target: *mut std::ffi::c_void,
    host: String,
    socks: bool,
    complete: bool,
}
// GSS handles are owned by this context and all access during a SOCKS exchange
// is serialized by one mutex before operations are moved to the relay task.
#[cfg(all(feature = "negotiate", unix))]
unsafe impl Send for NegotiateContext {}
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
type GssWrap = unsafe extern "C" fn(
    *mut u32,
    *mut std::ffi::c_void,
    i32,
    u32,
    *mut GssBuf,
    *mut i32,
    *mut GssBuf,
) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssUnwrap = unsafe extern "C" fn(
    *mut u32,
    *mut std::ffi::c_void,
    *mut GssBuf,
    *mut GssBuf,
    *mut i32,
    *mut u32,
) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssDeleteContext =
    unsafe extern "C" fn(*mut u32, *mut *mut std::ffi::c_void, *mut GssBuf) -> GssStatus;
#[cfg(all(feature = "negotiate", unix))]
type GssReleaseName = unsafe extern "C" fn(*mut u32, *mut *mut std::ffi::c_void) -> GssStatus;

#[cfg(all(feature = "negotiate", unix))]
unsafe fn import_gss_target(
    host: &str,
    socks: bool,
    import: GssImportName,
    release_name: Option<GssReleaseName>,
    mut display_status: impl FnMut(u32, i32) -> String,
) -> Result<*mut std::ffi::c_void> {
    let target = if socks {
        format!("SERVICE:socks@{host}")
    } else {
        format!("HTTP@{host}")
    };
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
    let status = unsafe {
        import(
            &mut minor,
            &mut name,
            if socks {
                std::ptr::null_mut()
            } else {
                &mut name_oid
            },
            &mut imported,
        )
    };
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
            "GSSAPI name import failed for {target}: major={status} ({major_text}), minor={minor} ({minor_text})"
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
        Self::new_for_service(host, false)
    }
    pub(crate) fn new_socks(host: &str) -> Result<Self> {
        Self::new_for_service(host, true)
    }
    fn new_for_service(host: &str, socks: bool) -> Result<Self> {
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
            let target = import_gss_target(host, socks, *import, release_name, |status, kind| {
                gss_status_text(&lib, status, kind)
            })?;
            Ok(Self {
                lib,
                ctx: std::ptr::null_mut(),
                target,
                host: host.to_owned(),
                socks,
                complete: false,
            })
        }
    }
    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        self.step_with_status(server_token).map(|(token, _)| token)
    }
    pub(crate) fn step_with_status(
        &mut self,
        server_token: Option<&[u8]>,
    ) -> Result<(Option<Vec<u8>>, bool)> {
        unsafe {
            let f: libloading::Symbol<GssInitSecContext> = self
                .lib
                .get(b"gss_init_sec_context\0")
                .context(format!("loading GSSAPI context step for {}", self.host))?;
            let (ctx, target, socks, host, lib) = (
                &mut self.ctx,
                self.target,
                self.socks,
                self.host.as_str(),
                &self.lib,
            );
            let (token, complete) = gss_step(
                GssStepRequest {
                    ctx,
                    target,
                    socks,
                    host,
                    server_token,
                },
                *f,
                |minor, buffer| release_gss_buffer(lib, minor, buffer),
                |status, kind| gss_status_text(lib, status, kind),
            )?;
            self.complete = complete;
            Ok((token, complete))
        }
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
    pub(crate) fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>> {
        unsafe {
            let wrap: libloading::Symbol<GssWrap> = self.lib.get(b"gss_wrap\0")?;
            let (ctx, host, lib) = (&mut self.ctx, self.host.as_str(), &self.lib);
            gss_wrap_message(
                ctx,
                host,
                message,
                confidential,
                *wrap,
                |minor, buffer| release_gss_buffer(lib, minor, buffer),
                |status, kind| gss_status_text(lib, status, kind),
            )
        }
    }
    pub(crate) fn unwrap(
        &mut self,
        message: &[u8],
        require_confidentiality: bool,
    ) -> Result<Vec<u8>> {
        unsafe {
            let unwrap: libloading::Symbol<GssUnwrap> = self.lib.get(b"gss_unwrap\0")?;
            let (ctx, host, lib) = (&mut self.ctx, self.host.as_str(), &self.lib);
            gss_unwrap_message(
                ctx,
                host,
                message,
                require_confidentiality,
                *unwrap,
                |minor, buffer| release_gss_buffer(lib, minor, buffer),
                |status, kind| gss_status_text(lib, status, kind),
            )
        }
    }
}

#[cfg(all(feature = "negotiate", unix))]
struct GssStepRequest<'a> {
    ctx: &'a mut *mut std::ffi::c_void,
    target: *mut std::ffi::c_void,
    socks: bool,
    host: &'a str,
    server_token: Option<&'a [u8]>,
}

#[cfg(all(feature = "negotiate", unix))]
unsafe fn gss_step(
    request: GssStepRequest<'_>,
    init: GssInitSecContext,
    mut release_buffer: impl FnMut(&mut u32, &mut GssBuf),
    mut display_status: impl FnMut(u32, i32) -> String,
) -> Result<(Option<Vec<u8>>, bool)> {
    let GssStepRequest {
        ctx,
        target,
        socks,
        host,
        server_token,
    } = request;
    let mut input = GssBuf {
        len: server_token.map_or(0, |token| token.len()),
        value: server_token.map_or(std::ptr::null_mut(), |token| {
            token.as_ptr() as *mut std::ffi::c_void
        }),
    };
    let mut output = GssBuf {
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
    let status = unsafe {
        init(
            &mut minor,
            std::ptr::null_mut(),
            ctx,
            target,
            if socks {
                std::ptr::null_mut()
            } else {
                &mut mech
            },
            if socks { 15 } else { 2 },
            0,
            std::ptr::null_mut(),
            &mut input,
            std::ptr::null_mut(),
            &mut output,
            &mut flags,
            std::ptr::null_mut(),
        )
    };
    let error = (status as u32 & 0xffff_0000) != 0;
    let token = if output.len == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(output.value.cast::<u8>(), output.len).to_vec() })
    };
    release_buffer(&mut minor, &mut output);
    if error {
        return Err(anyhow!(
            "Negotiate token step for {host} failed: major={status} ({}), minor={minor} ({})",
            display_status(status as u32, 1),
            display_status(minor, 2)
        ));
    }
    Ok((token, (status as u32 & 0xffff) == 0))
}

#[cfg(all(feature = "negotiate", unix))]
unsafe fn gss_wrap_message(
    ctx: &mut *mut std::ffi::c_void,
    host: &str,
    message: &[u8],
    confidential: bool,
    wrap: GssWrap,
    mut release_buffer: impl FnMut(&mut u32, &mut GssBuf),
    mut display_status: impl FnMut(u32, i32) -> String,
) -> Result<Vec<u8>> {
    let mut input = GssBuf {
        len: message.len(),
        value: message.as_ptr() as *mut _,
    };
    let mut output = GssBuf {
        len: 0,
        value: std::ptr::null_mut(),
    };
    let mut minor = 0;
    let mut conf_state = 0;
    let status = unsafe {
        wrap(
            &mut minor,
            *ctx,
            i32::from(confidential),
            0,
            &mut input,
            &mut conf_state,
            &mut output,
        )
    };
    let result = if output.value.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output.value.cast::<u8>(), output.len).to_vec() }
    };
    release_buffer(&mut minor, &mut output);
    if (status as u32 & 0xffff_0000) != 0 {
        return Err(anyhow!(
            "GSSAPI wrap failed for {host}: {}",
            display_status(status as u32, 1)
        ));
    }
    if confidential && conf_state == 0 {
        return Err(anyhow!(
            "GSSAPI did not provide requested confidentiality for {host}"
        ));
    }
    Ok(result)
}

#[cfg(all(feature = "negotiate", unix))]
unsafe fn gss_unwrap_message(
    ctx: &mut *mut std::ffi::c_void,
    host: &str,
    message: &[u8],
    require_confidentiality: bool,
    unwrap: GssUnwrap,
    mut release_buffer: impl FnMut(&mut u32, &mut GssBuf),
    mut display_status: impl FnMut(u32, i32) -> String,
) -> Result<Vec<u8>> {
    let mut input = GssBuf {
        len: message.len(),
        value: message.as_ptr() as *mut _,
    };
    let mut output = GssBuf {
        len: 0,
        value: std::ptr::null_mut(),
    };
    let mut minor = 0;
    let mut conf_state = 0;
    let mut qop_state = 0;
    let status = unsafe {
        unwrap(
            &mut minor,
            *ctx,
            &mut input,
            &mut output,
            &mut conf_state,
            &mut qop_state,
        )
    };
    let result = if output.value.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output.value.cast::<u8>(), output.len).to_vec() }
    };
    release_buffer(&mut minor, &mut output);
    if (status as u32 & 0xffff_0000) != 0 {
        return Err(anyhow!(
            "GSSAPI unwrap failed for {host}: {}",
            display_status(status as u32, 1)
        ));
    }
    if require_confidentiality && conf_state == 0 {
        return Err(anyhow!("SOCKS5 GSSAPI token lacks confidentiality"));
    }
    Ok(result)
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
    pub(crate) fn new_socks(_: &str) -> Result<Self> {
        Err(anyhow!("native GSSAPI unavailable"))
    }
    pub(crate) fn step_with_status(&mut self, _: Option<&[u8]>) -> Result<(Option<Vec<u8>>, bool)> {
        Err(anyhow!("native GSSAPI unavailable"))
    }
    pub(crate) fn is_complete(&self) -> bool {
        false
    }
    pub(crate) fn wrap(&mut self, _: &[u8], _: bool) -> Result<Vec<u8>> {
        Err(anyhow!("native GSSAPI unavailable"))
    }
    pub(crate) fn unwrap(&mut self, _: &[u8], _: bool) -> Result<Vec<u8>> {
        Err(anyhow!("native GSSAPI unavailable"))
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
#[repr(C)]
struct SecPkgContextSizes {
    max_token: u32,
    max_signature: u32,
    block_size: u32,
    security_trailer: u32,
}
#[cfg(all(feature = "negotiate", windows))]
type QueryContextAttributesW =
    unsafe extern "system" fn(*mut SecHandle, u32, *mut std::ffi::c_void) -> i32;
#[cfg(all(feature = "negotiate", windows))]
type EncryptMessage =
    unsafe extern "system" fn(*mut SecHandle, u32, *mut SecBufferDesc, u32) -> i32;
#[cfg(all(feature = "negotiate", windows))]
type DecryptMessage =
    unsafe extern "system" fn(*mut SecHandle, *mut SecBufferDesc, u32, *mut u32) -> i32;
#[cfg(all(feature = "negotiate", windows))]
type CompleteAuthToken = unsafe extern "system" fn(*mut SecHandle, *mut SecBufferDesc) -> i32;
#[cfg(all(feature = "negotiate", windows))]
pub struct NegotiateContext {
    lib: libloading::Library,
    cred: SecHandle,
    ctx: SecHandle,
    target: Vec<u16>,
    socks: bool,
    complete: bool,
}
// SSPI handles are owned by this context and serialized during relay use.
#[cfg(all(feature = "negotiate", windows))]
unsafe impl Send for NegotiateContext {}
#[cfg(all(feature = "negotiate", windows))]
impl NegotiateContext {
    pub fn new(host: &str) -> Result<Self> {
        Self::new_for_service(host, false)
    }
    pub(crate) fn new_socks(host: &str) -> Result<Self> {
        Self::new_for_service(host, true)
    }
    fn new_for_service(host: &str, socks: bool) -> Result<Self> {
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
                target: format!("{}{host}", if socks { "socks/" } else { "HTTP/" })
                    .encode_utf16()
                    .chain(Some(0))
                    .collect(),
                socks,
                complete: false,
            })
        }
    }
    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        self.step_with_status(server_token).map(|(token, _)| token)
    }
    pub(crate) fn step_with_status(
        &mut self,
        server_token: Option<&[u8]>,
    ) -> Result<(Option<Vec<u8>>, bool)> {
        unsafe {
            let init: libloading::Symbol<InitializeSecurityContextW> =
                self.lib.get(b"InitializeSecurityContextW\0")?;
            let mut input_buf = SecBuffer {
                size: server_token.map_or(0, |token| token.len() as u32),
                kind: 2,
                data: server_token.map_or(std::ptr::null_mut(), |token| token.as_ptr() as *mut _),
            };
            let mut input_desc = SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut input_buf,
            };
            let in_desc = if server_token.is_some() {
                &mut input_desc
            } else {
                std::ptr::null_mut()
            };
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
            let mut status = init(
                &mut self.cred,
                prior_ptr,
                self.target.as_ptr(),
                if self.socks { 0x0001_001f } else { 2 },
                0,
                0,
                in_desc,
                0,
                &mut next,
                &mut outdesc,
                &mut attrs,
                std::ptr::null_mut(),
            );
            if status == 0x0009_0313 || status == 0x0009_0314 {
                let complete_token: libloading::Symbol<CompleteAuthToken> =
                    self.lib.get(b"CompleteAuthToken\0")?;
                let completion = complete_token(&mut next, &mut outdesc);
                if completion < 0 {
                    return Err(anyhow!(
                        "CompleteAuthToken failed: 0x{:08x}",
                        completion as u32
                    ));
                }
                status = if status == 0x0009_0313 {
                    0
                } else {
                    0x0009_0312
                };
            }
            if status < 0 && status != 0x0009_0312 {
                return Err(anyhow!(
                    "InitializeSecurityContextW failed: 0x{:08x}",
                    status as u32
                ));
            }
            self.ctx = next;
            storage.truncate(outbuf.size as usize);
            self.complete = status == 0;
            if self.socks && self.complete && attrs & 2 == 0 {
                return Err(anyhow!(
                    "Windows Negotiate did not establish mutual authentication for SOCKS5"
                ));
            }
            Ok(((!storage.is_empty()).then_some(storage), self.complete))
        }
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
    pub(crate) fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>> {
        unsafe {
            let query: libloading::Symbol<QueryContextAttributesW> =
                self.lib.get(b"QueryContextAttributesW\0")?;
            let encrypt: libloading::Symbol<EncryptMessage> = self.lib.get(b"EncryptMessage\0")?;
            let mut sizes = SecPkgContextSizes {
                max_token: 0,
                max_signature: 0,
                block_size: 0,
                security_trailer: 0,
            };
            let status = query(
                &mut self.ctx,
                0,
                (&mut sizes as *mut SecPkgContextSizes).cast(),
            );
            if status < 0 {
                return Err(anyhow!(
                    "QueryContextAttributesW failed: 0x{:08x}",
                    status as u32
                ));
            }
            let header_size = sizes.security_trailer as usize;
            let padding_size = sizes.block_size as usize;
            let mut storage = vec![0u8; header_size + message.len() + padding_size];
            storage[header_size..header_size + message.len()].copy_from_slice(message);
            let mut buffers = [
                SecBuffer {
                    size: header_size as u32,
                    kind: 2,
                    data: storage.as_mut_ptr().cast(),
                },
                SecBuffer {
                    size: message.len() as u32,
                    kind: 1,
                    data: storage.as_mut_ptr().add(header_size).cast(),
                },
                SecBuffer {
                    size: padding_size as u32,
                    kind: 9,
                    data: storage.as_mut_ptr().add(header_size + message.len()).cast(),
                },
            ];
            let mut desc = SecBufferDesc {
                version: 0,
                count: buffers.len() as u32,
                buffers: buffers.as_mut_ptr(),
            };
            let qop = if confidential { 0 } else { 0x8000_0001 };
            let status = encrypt(&mut self.ctx, qop, &mut desc, 0);
            if status < 0 {
                return Err(anyhow!("EncryptMessage failed: 0x{:08x}", status as u32));
            }
            let mut output = Vec::new();
            for (buffer, start) in buffers
                .iter()
                .zip([0, header_size, header_size + message.len()])
            {
                output.extend_from_slice(&storage[start..start + buffer.size as usize]);
            }
            Ok(output)
        }
    }
    pub(crate) fn unwrap(
        &mut self,
        message: &[u8],
        require_confidentiality: bool,
    ) -> Result<Vec<u8>> {
        unsafe {
            let decrypt: libloading::Symbol<DecryptMessage> = self.lib.get(b"DecryptMessage\0")?;
            let mut storage = message.to_vec();
            let mut buffer = SecBuffer {
                size: storage.len() as u32,
                kind: 10,
                data: storage.as_mut_ptr().cast(),
            };
            let mut desc = SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut buffer,
            };
            let mut qop = 0;
            let status = decrypt(&mut self.ctx, &mut desc, 0, &mut qop);
            if status < 0 {
                return Err(anyhow!("DecryptMessage failed: 0x{:08x}", status as u32));
            }
            if require_confidentiality && qop == 0x8000_0001 {
                return Err(anyhow!("SOCKS5 GSSAPI token lacks confidentiality"));
            }
            let data = (0..desc.count as usize)
                .find_map(|index| {
                    let buffer = &*desc.buffers.add(index);
                    (buffer.kind & 0xffff == 1).then_some(buffer)
                })
                .ok_or_else(|| anyhow!("DecryptMessage returned no data buffer"))?;
            let start = (data.data as usize)
                .checked_sub(storage.as_ptr() as usize)
                .ok_or_else(|| anyhow!("DecryptMessage returned an invalid data buffer"))?;
            let end = start
                .checked_add(data.size as usize)
                .filter(|end| *end <= storage.len())
                .ok_or_else(|| anyhow!("DecryptMessage data exceeds the input token"))?;
            Ok(storage[start..end].to_vec())
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
    static SOCKS_IMPORT_MATCHES: AtomicUsize = AtomicUsize::new(0);
    static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static INIT_SOCKS_FLAGS: AtomicUsize = AtomicUsize::new(0);
    static INIT_NULL_MECH: AtomicUsize = AtomicUsize::new(0);
    static INIT_SERVER_TOKEN_MATCHES: AtomicUsize = AtomicUsize::new(0);
    static UNWRAP_CONFIDENTIALITY: AtomicUsize = AtomicUsize::new(0);

    unsafe fn fixture_set_buffer(buffer: *mut GssBuf, bytes: &[u8]) {
        let boxed = bytes.to_vec().into_boxed_slice();
        unsafe {
            (*buffer).len = boxed.len();
            (*buffer).value = Box::into_raw(boxed).cast();
        }
    }

    unsafe extern "C" fn fixture_release_owned_buffer(
        _: *mut u32,
        buffer: *mut GssBuf,
    ) -> GssStatus {
        unsafe {
            if !(*buffer).value.is_null() {
                let raw =
                    std::ptr::slice_from_raw_parts_mut((*buffer).value.cast::<u8>(), (*buffer).len);
                drop(Box::from_raw(raw));
                (*buffer).len = 0;
                (*buffer).value = std::ptr::null_mut();
            }
        }
        0
    }

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

    unsafe extern "C" fn fixture_import_socks_name(
        _: *mut u32,
        name: *mut GssBuf,
        oid: *mut GssOid,
        output: *mut *mut std::ffi::c_void,
    ) -> GssStatus {
        let bytes = unsafe { std::slice::from_raw_parts((*name).value.cast::<u8>(), (*name).len) };
        if bytes == b"SERVICE:socks@proxy.fixture.test" && oid.is_null() {
            SOCKS_IMPORT_MATCHES.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { *output = std::ptr::NonNull::<u8>::dangling().as_ptr().cast() };
        0
    }

    unsafe extern "C" fn fixture_init_sec_context(
        _: *mut u32,
        credential: *mut std::ffi::c_void,
        context: *mut *mut std::ffi::c_void,
        target: *mut std::ffi::c_void,
        mech: *mut GssOid,
        requested_flags: u32,
        _: u32,
        _: *mut std::ffi::c_void,
        input: *mut GssBuf,
        _: *mut *mut GssOid,
        output: *mut GssBuf,
        _: *mut u32,
        _: *mut u32,
    ) -> GssStatus {
        if credential.is_null()
            && target == std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
            && mech.is_null()
            && requested_flags == 15
        {
            INIT_SOCKS_FLAGS.fetch_add(1, Ordering::SeqCst);
        }
        if mech.is_null() {
            INIT_NULL_MECH.fetch_add(1, Ordering::SeqCst);
        }
        let step = INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        let input_len = unsafe { (*input).len };
        let input_bytes = if input_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts((*input).value.cast::<u8>(), input_len) }
        };
        if step == 0 {
            unsafe {
                *context = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
                fixture_set_buffer(output, b"client-first");
            }
            1
        } else if input_bytes == b"server-challenge" {
            INIT_SERVER_TOKEN_MATCHES.fetch_add(1, Ordering::SeqCst);
            unsafe { fixture_set_buffer(output, b"client-final") };
            0
        } else {
            0x0001_0000
        }
    }

    unsafe extern "C" fn fixture_init_sec_context_error(
        minor: *mut u32,
        _: *mut std::ffi::c_void,
        _: *mut *mut std::ffi::c_void,
        _: *mut std::ffi::c_void,
        _: *mut GssOid,
        _: u32,
        _: u32,
        _: *mut std::ffi::c_void,
        _: *mut GssBuf,
        _: *mut *mut GssOid,
        _: *mut GssBuf,
        _: *mut u32,
        _: *mut u32,
    ) -> GssStatus {
        unsafe { *minor = 23 };
        0x0001_0000
    }

    unsafe extern "C" fn fixture_wrap(
        _: *mut u32,
        _: *mut std::ffi::c_void,
        confidential: i32,
        _: u32,
        _: *mut GssBuf,
        conf_state: *mut i32,
        output: *mut GssBuf,
    ) -> GssStatus {
        unsafe {
            *conf_state = confidential;
            fixture_set_buffer(output, b"wrapped-token");
        }
        0
    }

    unsafe extern "C" fn fixture_wrap_without_confidentiality(
        _: *mut u32,
        _: *mut std::ffi::c_void,
        _: i32,
        _: u32,
        _: *mut GssBuf,
        conf_state: *mut i32,
        output: *mut GssBuf,
    ) -> GssStatus {
        unsafe {
            *conf_state = 0;
            fixture_set_buffer(output, b"wrapped-token");
        }
        0
    }

    unsafe extern "C" fn fixture_wrap_error(
        _: *mut u32,
        _: *mut std::ffi::c_void,
        _: i32,
        _: u32,
        _: *mut GssBuf,
        _: *mut i32,
        _: *mut GssBuf,
    ) -> GssStatus {
        0x0001_0000
    }

    unsafe extern "C" fn fixture_unwrap(
        _: *mut u32,
        _: *mut std::ffi::c_void,
        input: *mut GssBuf,
        output: *mut GssBuf,
        conf_state: *mut i32,
        _: *mut u32,
    ) -> GssStatus {
        let input =
            unsafe { std::slice::from_raw_parts((*input).value.cast::<u8>(), (*input).len) };
        let confidential = UNWRAP_CONFIDENTIALITY.load(Ordering::SeqCst) as i32;
        unsafe {
            *conf_state = confidential;
            fixture_set_buffer(output, input);
        }
        0
    }

    unsafe extern "C" fn fixture_unwrap_error(
        _: *mut u32,
        _: *mut std::ffi::c_void,
        _: *mut GssBuf,
        _: *mut GssBuf,
        _: *mut i32,
        _: *mut u32,
    ) -> GssStatus {
        0x0001_0000
    }

    fn fixture_status(status: u32, kind: i32) -> String {
        format!("status {status} kind {kind}")
    }

    fn fixture_buffer_release(minor: &mut u32, buffer: &mut GssBuf) {
        unsafe { fixture_release_owned_buffer(minor, buffer) };
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
                false,
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
    fn socks_gss_name_import_uses_the_socks_service_without_a_name_oid() {
        let _guard = TEST_LOCK.lock().unwrap();
        SOCKS_IMPORT_MATCHES.store(0, Ordering::SeqCst);
        let mut target = unsafe {
            import_gss_target(
                "proxy.fixture.test",
                true,
                fixture_import_socks_name,
                Some(fixture_release_name),
                fixture_status,
            )
        }
        .unwrap();

        assert_eq!(SOCKS_IMPORT_MATCHES.load(Ordering::SeqCst), 1);
        unsafe {
            release_gss_handles(
                &mut std::ptr::null_mut(),
                &mut target,
                None,
                None,
                Some(fixture_release_name),
            );
        }
        assert!(target.is_null());
    }

    #[test]
    fn gss_context_step_handles_continue_complete_and_error_statuses() {
        let _guard = TEST_LOCK.lock().unwrap();
        INIT_CALLS.store(0, Ordering::SeqCst);
        INIT_SOCKS_FLAGS.store(0, Ordering::SeqCst);
        INIT_NULL_MECH.store(0, Ordering::SeqCst);
        INIT_SERVER_TOKEN_MATCHES.store(0, Ordering::SeqCst);
        let mut context = std::ptr::null_mut();
        let target = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();

        let (token, complete) = unsafe {
            gss_step(
                GssStepRequest {
                    ctx: &mut context,
                    target,
                    socks: true,
                    host: "proxy.fixture.test",
                    server_token: None,
                },
                fixture_init_sec_context,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap();
        assert_eq!(token.as_deref(), Some(b"client-first".as_slice()));
        assert!(!complete);
        assert!(!context.is_null());

        let (token, complete) = unsafe {
            gss_step(
                GssStepRequest {
                    ctx: &mut context,
                    target,
                    socks: true,
                    host: "proxy.fixture.test",
                    server_token: Some(b"server-challenge"),
                },
                fixture_init_sec_context,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap();
        assert_eq!(token.as_deref(), Some(b"client-final".as_slice()));
        assert!(complete);
        assert_eq!(INIT_SOCKS_FLAGS.load(Ordering::SeqCst), 2);
        assert_eq!(INIT_NULL_MECH.load(Ordering::SeqCst), 2);
        assert_eq!(INIT_SERVER_TOKEN_MATCHES.load(Ordering::SeqCst), 1);

        let error = unsafe {
            gss_step(
                GssStepRequest {
                    ctx: &mut context,
                    target,
                    socks: true,
                    host: "proxy.fixture.test",
                    server_token: None,
                },
                fixture_init_sec_context_error,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap_err();
        assert!(error.to_string().contains("proxy.fixture.test"));
        assert!(error.to_string().contains("status 65536 kind 1"));
        assert!(error.to_string().contains("status 23 kind 2"));
    }

    #[test]
    fn gss_wrap_and_unwrap_enforce_confidentiality_and_report_native_errors() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut context = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();

        let wrapped = unsafe {
            gss_wrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                true,
                fixture_wrap,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap();
        assert_eq!(wrapped, b"wrapped-token");

        let error = unsafe {
            gss_wrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                true,
                fixture_wrap_without_confidentiality,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("did not provide requested confidentiality")
        );

        let error = unsafe {
            gss_wrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                false,
                fixture_wrap_error,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap_err();
        assert!(error.to_string().contains("GSSAPI wrap failed"));
        assert!(error.to_string().contains("status 65536 kind 1"));

        UNWRAP_CONFIDENTIALITY.store(1, Ordering::SeqCst);
        let unwrapped = unsafe {
            gss_unwrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                true,
                fixture_unwrap,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap();
        assert_eq!(unwrapped, b"payload");

        UNWRAP_CONFIDENTIALITY.store(0, Ordering::SeqCst);
        let error = unsafe {
            gss_unwrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                true,
                fixture_unwrap,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap_err();
        assert!(error.to_string().contains("lacks confidentiality"));

        let error = unsafe {
            gss_unwrap_message(
                &mut context,
                "proxy.fixture.test",
                b"payload",
                false,
                fixture_unwrap_error,
                fixture_buffer_release,
                fixture_status,
            )
        }
        .unwrap_err();
        assert!(error.to_string().contains("GSSAPI unwrap failed"));
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
}
