//! Upstream proxy authentication.
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::HeaderValue;
use std::{
    collections::HashMap,
    fmt, fs,
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Clone, Default)]
pub struct CredentialStore(Arc<RwLock<Credentials>>);
#[derive(Default)]
struct Credentials {
    hosts: HashMap<String, (String, String)>,
    default: Option<(String, String)>,
}
impl fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialStore")
            .field("hosts", &self.hosts())
            .field(
                "has_default",
                &self.0.read().map(|x| x.default.is_some()).unwrap_or(false),
            )
            .finish()
    }
}
impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_netrc(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse(&fs::read_to_string(path)?)
    }
    pub fn parse(input: &str) -> Result<Self> {
        let t = netrc_tokens(input)?;
        let (mut h, mut d) = (HashMap::new(), None);
        let mut i = 0;
        while i < t.len() {
            let kind = t[i].as_str();
            if kind != "machine" && kind != "default" {
                return Err(anyhow!("expected machine or default, found {kind}"));
            }
            i += 1;
            let host = if kind == "machine" {
                let x = t
                    .get(i)
                    .ok_or_else(|| anyhow!("missing machine name"))?
                    .clone();
                i += 1;
                Some(x)
            } else {
                None
            };
            let (mut login, mut password) = (None, None);
            while i < t.len() && t[i] != "machine" && t[i] != "default" {
                let key = t[i].as_str();
                i += 1;
                match key {
                    "login" | "user" => {
                        login = Some(t.get(i).ok_or_else(|| anyhow!("missing login"))?.clone());
                        i += 1
                    }
                    "password" | "passwd" => {
                        password =
                            Some(t.get(i).ok_or_else(|| anyhow!("missing password"))?.clone());
                        i += 1
                    }
                    "account" => {
                        if i < t.len() {
                            i += 1
                        }
                    }
                    x => return Err(anyhow!("unsupported netrc token {x}")),
                }
            }
            if let Some(host) = host {
                let u = login.ok_or_else(|| anyhow!("machine {host} has no login"))?;
                h.insert(host, (u, password.unwrap_or_default()));
            } else if let Some(u) = login {
                d = Some((u, password.unwrap_or_default()));
            }
        }
        Ok(Self(Arc::new(RwLock::new(Credentials {
            hosts: h,
            default: d,
        }))))
    }
    pub fn replace_netrc(&self, input: &str) -> Result<()> {
        let next = Self::parse(input)?;
        let replacement = next
            .0
            .read()
            .map_err(|_| anyhow!("credential store poisoned"))?;
        *self
            .0
            .write()
            .map_err(|_| anyhow!("credential store poisoned"))? = Credentials {
            hosts: replacement.hosts.clone(),
            default: replacement.default.clone(),
        };
        Ok(())
    }
    pub fn replace_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.replace_netrc(&fs::read_to_string(path)?)
    }
    pub fn hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .0
            .read()
            .map(|m| m.hosts.keys().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v
    }
    fn get(&self, host: &str) -> Option<(String, String)> {
        let m = self.0.read().ok()?;
        m.hosts.get(host).cloned().or_else(|| m.default.clone())
    }
}
fn netrc_tokens(s: &str) -> Result<Vec<String>> {
    let (mut o, mut c) = (vec![], String::new());
    let (mut quote, mut esc) = (None, false);
    let mut it = s.chars().peekable();
    while let Some(x) = it.next() {
        if esc {
            c.push(x);
            esc = false;
            continue;
        }
        if x == '\\' {
            esc = true;
            continue;
        }
        if let Some(q) = quote {
            if x == q {
                quote = None
            } else {
                c.push(x)
            };
            continue;
        }
        if x == '"' || x == '\'' {
            quote = Some(x);
            continue;
        }
        if x == '#' {
            while it.next().is_some_and(|z| z != '\n') {}
            if !c.is_empty() {
                o.push(std::mem::take(&mut c))
            };
            continue;
        }
        if x.is_whitespace() {
            if !c.is_empty() {
                o.push(std::mem::take(&mut c))
            }
        } else {
            c.push(x)
        }
    }
    if quote.is_some() {
        return Err(anyhow!("unterminated netrc quote"));
    }
    if !c.is_empty() {
        o.push(c)
    }
    Ok(o)
}

#[derive(Clone, Default)]
pub struct AuthFactory {
    mode: AuthMode,
}
#[derive(Clone, Default)]
enum AuthMode {
    #[default]
    None,
    Basic(CredentialStore),
    #[cfg(feature = "negotiate")]
    Negotiate(Vec<String>),
}
impl fmt::Debug for AuthFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            AuthMode::None => f.write_str("AuthFactory(None)"),
            AuthMode::Basic(s) => f.debug_tuple("AuthFactory(Basic)").field(s).finish(),
            #[cfg(feature = "negotiate")]
            AuthMode::Negotiate(h) => f.debug_tuple("AuthFactory(Negotiate)").field(h).finish(),
        }
    }
}
impl AuthFactory {
    pub fn no_auth() -> Self {
        Self::default()
    }
    pub fn basic(store: CredentialStore) -> Self {
        Self {
            mode: AuthMode::Basic(store),
        }
    }
    #[cfg(feature = "negotiate")]
    pub fn negotiate(hosts: Vec<String>) -> Self {
        Self {
            mode: AuthMode::Negotiate(hosts),
        }
    }
    pub async fn authorization(&self, host: &str) -> Result<Option<HeaderValue>> {
        let mode = self.mode.clone();
        let host = host.to_owned();
        let timeout_host = host.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::task::spawn_blocking(move || -> Result<Option<HeaderValue>> {
                match mode {
                    AuthMode::None => Ok(None),
                    AuthMode::Basic(s) => {
                        let (u, p) = s
                            .get(&host)
                            .ok_or_else(|| anyhow!("no credentials configured for {host}"))?;
                        let v = format!("Basic {}", STANDARD.encode(format!("{u}:{p}")));
                        Ok(Some(
                            HeaderValue::from_str(&v)
                                .context("invalid Basic authorization value")?,
                        ))
                    }
                    #[cfg(feature = "negotiate")]
                    AuthMode::Negotiate(hosts) => {
                        if !hosts.is_empty() && !hosts.iter().any(|h| h == &host) {
                            return Ok(None);
                        }
                        let mut context = NegotiateContext::new(&host).with_context(|| {
                            format!("initializing Negotiate for upstream {host}")
                        })?;
                        let token = context.step(None).with_context(|| {
                            format!("generating Negotiate token for upstream {host}")
                        })?;
                        Ok(token
                            .map(|t| {
                                HeaderValue::from_str(&format!("Negotiate {}", STANDARD.encode(t)))
                                    .context("invalid Negotiate header")
                            })
                            .transpose()?)
                    }
                }
            }),
        )
        .await
        .map_err(|_| anyhow!("authorization timed out for {timeout_host}"))?
        .context("authorization worker failed")?
    }
}

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
            let import: libloading::Symbol<
                unsafe extern "C" fn(
                    *mut u32,
                    *mut GssBuf,
                    *mut GssOid,
                    *mut *mut std::ffi::c_void,
                ) -> GssStatus,
            > = lib.get(b"gss_import_name\0")?;
            let mut ty = std::ptr::null_mut();
            let mut output = 0;
            let mut name = GssBuf {
                len: 0,
                value: std::ptr::null_mut(),
            };
            let target = format!("HTTP@{host}");
            name.len = target.len();
            name.value = target.as_ptr() as *mut _;
            // host-based service name OID 1.2.840.113554.1.2.1.4
            let mut name_oid_bytes: [u8; 10] =
                [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
            let mut name_oid = GssOid {
                len: 10,
                elements: name_oid_bytes.as_mut_ptr().cast(),
            };
            let status = import(&mut output, &mut name, &mut name_oid, &mut ty);
            if status != 0 {
                return Err(anyhow!(
                    "GSSAPI name import failed for HTTP@{host}: major={status} ({}), minor={output} ({})",
                    gss_status_text(&lib, status as u32, 1),
                    gss_status_text(&lib, output, 2)
                ));
            }
            Ok(Self {
                lib,
                ctx: std::ptr::null_mut(),
                target: ty,
                host: host.to_owned(),
            })
        }
    }
    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        unsafe {
            let f: libloading::Symbol<
                unsafe extern "C" fn(
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
                ) -> GssStatus,
            > = self
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
    if !buf.value.is_null() {
        if let Ok(f) = unsafe {
            lib.get::<unsafe extern "C" fn(*mut u32, *mut GssBuf) -> GssStatus>(
                b"gss_release_buffer\0",
            )
        } {
            unsafe {
                f(minor, buf);
            }
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
            if !self.ctx.is_null() {
                if let Ok(delete) =
                    self.lib.get::<unsafe extern "C" fn(
                        *mut u32,
                        *mut *mut std::ffi::c_void,
                        *mut GssBuf,
                    ) -> GssStatus>(b"gss_delete_sec_context\0")
                {
                    let mut minor = 0;
                    let mut out = GssBuf {
                        len: 0,
                        value: std::ptr::null_mut(),
                    };
                    delete(&mut minor, &mut self.ctx, &mut out);
                    if !out.value.is_null() {
                        if let Ok(release) =
                            self.lib.get::<unsafe extern "C" fn(*mut u32, *mut GssBuf)>(
                                b"gss_release_buffer\0",
                            )
                        {
                            release(&mut minor, &mut out)
                        }
                    }
                }
            }
            if !self.target.is_null() {
                if let Ok(release) = self
                    .lib
                    .get::<unsafe extern "C" fn(*mut u32, *mut *mut std::ffi::c_void) -> GssStatus>(
                        b"gss_release_name\0",
                    )
                {
                    let mut minor = 0;
                    release(&mut minor, &mut self.target);
                }
            }
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn netrc_default_replace() {
        let c = CredentialStore::parse("machine a login joe\ndefault login d password p").unwrap();
        assert_eq!(c.get("a"), Some(("joe".into(), "".into())));
        assert_eq!(c.get("b"), Some(("d".into(), "p".into())));
        assert!(c.replace_netrc("machine broken").is_err());
        assert_eq!(c.get("a").unwrap().0, "joe")
    }
    #[cfg(all(feature = "negotiate", unix))]
    #[test]
    fn native_gss_context_step_is_safe_without_a_ticket_fixture() {
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
    #[cfg(all(feature = "negotiate", unix))]
    #[test]
    #[ignore = "requires a configured native GSS identity or ticket cache"]
    fn native_gss_context_step_uses_host_based_spnego() {
        let mut context = NegotiateContext::new("localhost").unwrap();
        let token = context.step(None).unwrap().expect("initial SPNEGO token");
        assert!(!token.is_empty());
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
            let init: libloading::Symbol<
                unsafe extern "system" fn(
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
                ) -> i32,
            > = self.lib.get(b"InitializeSecurityContextW\0")?;
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
            if self.ctx.a != 0 || self.ctx.b != 0 {
                if let Ok(f) = self
                    .lib
                    .get::<unsafe extern "system" fn(*mut SecHandle) -> i32>(
                        b"DeleteSecurityContext\0",
                    )
                {
                    f(&mut self.ctx);
                }
            }
            if self.cred.a != 0 || self.cred.b != 0 {
                if let Ok(f) = self
                    .lib
                    .get::<unsafe extern "system" fn(*mut SecHandle) -> i32>(
                        b"FreeCredentialsHandle\0",
                    )
                {
                    f(&mut self.cred);
                }
            }
        }
    }
}
