// SPDX-License-Identifier: GPL-3.0-or-later
//! Secret prompting: either via an external `pinentry` program or a no-echo TTY
//! read.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Obtain a secret from the user. Uses `pinentry` when provided, otherwise reads
/// from the controlling TTY with echo disabled.
pub fn read_secret(prompt: &str, pinentry: Option<&Path>) -> Result<String> {
    match pinentry {
        Some(program) => read_via_pinentry(program, prompt),
        None => read_via_tty(prompt),
    }
}

fn read_via_pinentry(program: &Path, prompt: &str) -> Result<String> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning pinentry {:?}", program))?;

    let mut stdin = child.stdin.take().context("pinentry stdin")?;
    let mut stdout = BufReader::new(child.stdout.take().context("pinentry stdout")?);

    let mut line = String::new();
    // Greeting.
    stdout.read_line(&mut line)?;

    let send = |stdin: &mut std::process::ChildStdin, cmd: &str| -> Result<()> {
        stdin.write_all(cmd.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        Ok(())
    };

    send(&mut stdin, &format!("SETPROMPT {}", prompt))?;
    line.clear();
    stdout.read_line(&mut line)?; // OK

    send(&mut stdin, "GETPIN")?;

    let mut pin = None;
    loop {
        line.clear();
        if stdout.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end();
        if let Some(rest) = l.strip_prefix("D ") {
            pin = Some(rest.to_string());
        } else if l == "OK" || l.starts_with("OK ") {
            break;
        } else if l.starts_with("ERR") {
            bail!("pinentry error: {}", l);
        }
    }

    let _ = child.wait();
    pin.context("pinentry returned no secret")
}

fn read_via_tty(prompt: &str) -> Result<String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    use std::fs::OpenOptions;
    use std::io::Read;

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening /dev/tty for secret prompt")?;

    // Print the prompt.
    {
        let mut w = &tty;
        write!(w, "{}", prompt)?;
        w.flush()?;
    }

    // Disable echo for the read.
    let original = tcgetattr(&tty).context("tcgetattr")?;
    let mut raw = original.clone();
    raw.local_flags.remove(LocalFlags::ECHO);
    tcsetattr(&tty, SetArg::TCSANOW, &raw).context("disabling echo")?;

    let mut secret = String::new();
    let mut byte = [0u8; 1];
    let mut reader = &tty;
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break;
                }
                secret.push(byte[0] as char);
            }
            Err(e) => {
                let _ = tcsetattr(&tty, SetArg::TCSANOW, &original);
                return Err(e).context("reading secret");
            }
        }
    }

    // Restore echo and emit the newline the user's Enter didn't echo.
    let _ = tcsetattr(&tty, SetArg::TCSANOW, &original);
    let mut w = &tty;
    let _ = writeln!(w);

    Ok(secret)
}
