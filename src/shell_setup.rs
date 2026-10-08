//! Generate shell code for proxy environment variables and CLI completion.
use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use std::{ffi::OsString, io};

#[derive(Parser)]
#[command(name = "unproxy", disable_help_subcommand = true)]
struct SetupCli {
    #[command(subcommand)]
    command: SetupCommand,
}

#[derive(Subcommand)]
enum SetupCommand {
    /// Print shell code to configure proxy variables and command completion.
    ShellSetup(ShellSetupArgs),
}

#[derive(Args)]
struct ShellSetupArgs {
    /// The shell that will evaluate the generated code.
    shell: TargetShell,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TargetShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Cmd,
}

impl TargetShell {
    fn proxy_code(self, proxy: &str) -> String {
        let bypass = "localhost,127.0.0.1,::1";
        match self {
            Self::Bash | Self::Zsh => format!(
                "export http_proxy='{proxy}'\nexport https_proxy='{proxy}'\nexport HTTP_PROXY='{proxy}'\nexport HTTPS_PROXY='{proxy}'\nexport no_proxy='{bypass}'\nexport NO_PROXY='{bypass}'\n"
            ),
            Self::Fish => format!(
                "set -gx http_proxy '{proxy}'\nset -gx https_proxy '{proxy}'\nset -gx HTTP_PROXY '{proxy}'\nset -gx HTTPS_PROXY '{proxy}'\nset -gx no_proxy '{bypass}'\nset -gx NO_PROXY '{bypass}'\n"
            ),
            Self::Powershell => format!(
                "$env:http_proxy = '{proxy}'\n$env:https_proxy = '{proxy}'\n$env:HTTP_PROXY = '{proxy}'\n$env:HTTPS_PROXY = '{proxy}'\n$env:no_proxy = '{bypass}'\n$env:NO_PROXY = '{bypass}'\n"
            ),
            // cmd.exe has no facility for evaluating a child process's output. The
            // documented `for /f` invocation executes each emitted SET command in
            // the current cmd.exe process.
            Self::Cmd => format!(
                "set \"http_proxy={proxy}\"\nset \"https_proxy={proxy}\"\nset \"HTTP_PROXY={proxy}\"\nset \"HTTPS_PROXY={proxy}\"\nset \"no_proxy={bypass}\"\nset \"NO_PROXY={bypass}\"\n"
            ),
        }
    }

    fn completion_shell(self) -> Option<Shell> {
        match self {
            Self::Bash => Some(Shell::Bash),
            Self::Zsh => Some(Shell::Zsh),
            Self::Fish => Some(Shell::Fish),
            Self::Powershell => Some(Shell::PowerShell),
            Self::Cmd => None,
        }
    }
}

/// Parse and execute `unproxy shell-setup <shell>`.
pub fn run(args: Vec<OsString>) -> Result<()> {
    let cli = SetupCli::try_parse_from(args).context("parse shell-setup command")?;
    let SetupCommand::ShellSetup(setup) = cli.command;
    let read_settings = std::env::var_os("UNPROXY_NORC").is_none_or(|value| value.is_empty());
    let config_args = crate::config::parse_main_from(vec!["unproxy".into()], read_settings)?;
    let addr = config_args
        .listen_addrs()?
        .into_iter()
        .next()
        .context("no proxy listener configured")?;
    let proxy = format!("http://{addr}");

    let mut output = setup.shell.proxy_code(&proxy).into_bytes();
    if let Some(shell) = setup.shell.completion_shell() {
        let mut command = crate::config::MainArgs::command();
        command = command.subcommand(clap::Command::new("shell-setup").arg(
            clap::Arg::new("shell").required(true).value_parser([
                "bash",
                "zsh",
                "fish",
                "powershell",
                "cmd",
            ]),
        ));
        generate(shell, &mut command, "unproxy", &mut output);
    }
    io::Write::write_all(&mut io::stdout().lock(), &output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::TargetShell;

    #[test]
    fn emits_native_environment_assignment_syntax() {
        assert!(
            TargetShell::Bash
                .proxy_code("http://127.0.0.1:3128")
                .contains("export http_proxy=")
        );
        assert!(
            TargetShell::Fish
                .proxy_code("http://127.0.0.1:3128")
                .contains("set -gx no_proxy")
        );
        assert!(
            TargetShell::Powershell
                .proxy_code("http://127.0.0.1:3128")
                .contains("$env:https_proxy")
        );
        assert!(
            TargetShell::Cmd
                .proxy_code("http://127.0.0.1:3128")
                .contains("set \"no_proxy=")
        );
    }
}
