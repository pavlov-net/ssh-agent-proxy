/// Non-Windows stub: the proxy is never launched by the SCM on this platform.
pub fn is_windows_service() -> bool {
    false
}

/// Non-Windows stub: nothing to do.
pub fn run_as_windows_service() {}

/// Non-Windows stub: install/uninstall are Windows-only subcommands.
pub fn run_service_cmd(_cmd: &str, _args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    Err("install/uninstall are only available on Windows".into())
}
