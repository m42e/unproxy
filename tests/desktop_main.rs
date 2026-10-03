fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let dir = tempfile::tempdir()?;
        let child = std::path::Path::new(env!("CARGO_BIN_EXE_unproxy"));
        let pac = dir.path().join("proxy.pac");
        std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}\n")?;
        unproxy::desktop::run_native_main_thread_probe(dir.path(), child, &pac)?;
    }
    Ok(())
}
