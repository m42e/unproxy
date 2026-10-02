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
            if let Some(u) = login {
                let pair = (u, password.unwrap_or_default());
                if let Some(host) = host {
                    h.insert(host, pair);
                } else {
                    d = Some(pair)
                }
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
                        };
                        let token = NegotiateContext::new(&host)?.step(None)?;
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
}
#[cfg(all(feature = "negotiate", unix))]
#[repr(C)]
struct GssBuf {
    len: u32,
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
            let names: [&str; 3] = ["libgssapi_krb5.so.2", "libgssapi.so.3", "libgssapi.dylib"];
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
            name.len = target.len() as u32;
            name.value = target.as_ptr() as *mut _;
            // host-based service name OID 1.2.840.113554.1.2.1.4
            let mut name_oid = GssOid {
                len: 10,
                elements: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04].as_mut_ptr()
                    as *mut _,
            };
            let status = import(&mut output, &mut name, &mut name_oid, &mut ty);
            if status != 0 {
                return Err(anyhow!("GSSAPI name import failed ({status})"));
            }
            Ok(Self {
                lib,
                ctx: std::ptr::null_mut(),
                target: ty,
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
                    *mut GssOid,
                    *mut GssBuf,
                    *mut u32,
                    *mut u32,
                ) -> GssStatus,
            > = self.lib.get(b"gss_init_sec_context\0")?;
            let mut input = GssBuf {
                len: server_token.map_or(0, |v| v.len() as u32),
                value: server_token.map_or(std::ptr::null_mut::<std::ffi::c_void>(), |v| {
                    v.as_ptr() as *mut std::ffi::c_void
                }),
            };
            let mut out = GssBuf {
                len: 0,
                value: std::ptr::null_mut(),
            };
            let mut mech = GssOid {
                len: 6,
                elements: [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02].as_mut_ptr() as *mut _,
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
            if status != 0 && status != 1 && status != 8 {
                return Err(anyhow!(
                    "GSSAPI context step failed (major {status}, minor {minor})"
                ));
            }
            if out.len == 0 {
                return Ok(None);
            }
            let bytes =
                std::slice::from_raw_parts(out.value as *const u8, out.len as usize).to_vec();
            if let Ok(release) = self
                .lib
                .get::<unsafe extern "C" fn(*mut u32, *mut GssBuf)>(b"gss_release_buffer\0")
            {
                let mut m = 0;
                release(&mut m, &mut out)
            }
            Ok(Some(bytes))
        }
    }
}
#[cfg(all(feature = "negotiate", not(unix), not(windows)))]
pub struct NegotiateContext;
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
}

#[cfg(all(feature = "negotiate", windows))]
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
    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        unsafe {
            let init: libloading::Symbol<
                unsafe extern "system" fn(
                    *mut SecHandle,
                    *const u16,
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
            let inbuf = server_token.map(|s| SecBuffer {
                size: s.len() as u32,
                kind: 2,
                data: s.as_ptr() as *mut _,
            });
            let mut in_desc = inbuf.map(|mut x| SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut x,
            });
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
                &self.ctx,
                self.target.as_ptr(),
                2,
                0,
                0,
                in_desc
                    .as_mut()
                    .map_or(std::ptr::null_mut(), |x| x as *mut _),
                0,
                &mut self.ctx,
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
            storage.truncate(outbuf.size as usize);
            Ok((!storage.is_empty()).then_some(storage))
        }
    }
}
