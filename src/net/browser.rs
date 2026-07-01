// SPDX-License-Identifier: GPL-3.0-or-later
//! Portable SSO browser launch.
//!
//! The client usually runs as root, but the browser must open in the login
//! user's own session so *their* default browser — with its live SSO cookies —
//! is used (that direct, already-signed-in path is what completes most logins
//! without re-prompting). We identify that user authoritatively from
//! systemd-logind's active local graphical session, which works even when we're
//! launched by a system service such as NetworkManager (no sudo/login ancestry
//! to infer it from), then run the opener inside that session. If none of that
//! is possible we print the URL for the user to open manually.

use nix::unistd::{Uid, User};
use std::fs;
use std::process::Command;

/// Attempt to open `url` in the login user's default browser. Never fails hard —
/// on any problem it logs the URL for the user to open manually.
pub fn open_url(url: &str) {
    if let Some(uid) = original_user_uid()
        && uid != 0
        && let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid))
    {
        if try_open_as_user(&user.name, url) {
            return;
        }
    } else if try_open_plain(url) {
        return;
    }

    tracing::error!("Could not open a browser automatically.");
    tracing::error!("Please open this URL to complete SSO login:\n  {}", url);
}

/// Open `url` as `user` so the opener resolves to their default browser (and its
/// existing SSO session), even though we run as root. Prefers the systemd user
/// session on Linux; falls back to `su` (which also covers macOS, where
/// `opener()` is `open` and there is no `systemd-run`).
fn try_open_as_user(user: &str, url: &str) -> bool {
    // systemd user session (Linux desktops running systemd --user).
    if command_exists("systemd-run") {
        let ok = Command::new("systemd-run")
            .args([
                "--quiet",
                "--pipe",
                "--wait",
                "--user",
                "--machine",
                &format!("{}@.host", user),
                "--",
            ])
            .arg(opener())
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    // Non-systemd fallback (incl. macOS): run the opener directly as the user.
    Command::new("su")
        .args([user, "-c", &format!("{} '{}'", opener(), url)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_open_plain(url: &str) -> bool {
    Command::new(opener())
        .arg(url)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The platform's URL opener.
fn opener() -> &'static str {
    if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    }
}

/// Discover the human user whose session a browser should open in. Ordered by
/// authority: the active local graphical session (works for a system-service
/// launch like NetworkManager), then `sudo`, then the audit login session.
fn original_user_uid() -> Option<u32> {
    if let Some(uid) = logind_active_uid() {
        return Some(uid);
    }
    if let Ok(v) = std::env::var("SUDO_UID")
        && let Ok(uid) = v.parse::<u32>()
    {
        return Some(uid);
    }
    if let Ok(content) = fs::read_to_string("/proc/self/loginuid")
        && let Ok(uid) = content.trim().parse::<u32>()
        && uid != u32::MAX
    {
        return Some(uid);
    }
    None
}

/// The owner of the active, local, graphical logind session — the authoritative
/// "who is at the keyboard", independent of process ancestry or sudo.
fn logind_active_uid() -> Option<u32> {
    let list = Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;
    if !list.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&list.stdout).lines() {
        let Some(id) = line.split_whitespace().next() else {
            continue;
        };
        let show = Command::new("loginctl")
            .args([
                "show-session",
                id,
                "-p",
                "Active",
                "-p",
                "Remote",
                "-p",
                "Type",
                "-p",
                "User",
            ])
            .output()
            .ok()?;
        if show.status.success()
            && let Some(uid) = parse_graphical_session_uid(&String::from_utf8_lossy(&show.stdout))
        {
            return Some(uid);
        }
    }
    None
}

/// From `loginctl show-session` `Key=Value` output, return the owner uid iff the
/// session is active, local, and graphical (i.e. a browser can open in it).
fn parse_graphical_session_uid(props: &str) -> Option<u32> {
    let (mut active, mut remote, mut graphical, mut uid) = (false, false, false, None);
    for line in props.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Active" => active = val == "yes",
            "Remote" => remote = val == "yes",
            "Type" => graphical = matches!(val, "wayland" | "x11" | "mir"),
            "User" => uid = val.trim().parse::<u32>().ok(),
            _ => {}
        }
    }
    if active && !remote && graphical {
        uid
    } else {
        None
    }
}

fn command_exists(name: &str) -> bool {
    std::env::var("PATH")
        .ok()
        .map(|p| {
            p.split(':')
                .any(|d| std::path::Path::new(d).join(name).is_file())
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::parse_graphical_session_uid;

    #[test]
    fn picks_active_local_graphical_session() {
        assert_eq!(
            parse_graphical_session_uid("Active=yes\nRemote=no\nType=wayland\nUser=1000\n"),
            Some(1000)
        );
        // Property order doesn't matter; x11 counts too.
        assert_eq!(
            parse_graphical_session_uid("User=1001\nType=x11\nActive=yes\nRemote=no"),
            Some(1001)
        );
    }

    #[test]
    fn rejects_inactive_remote_or_nongraphical() {
        assert_eq!(
            parse_graphical_session_uid("Active=no\nRemote=no\nType=wayland\nUser=1000"),
            None
        );
        assert_eq!(
            parse_graphical_session_uid("Active=yes\nRemote=no\nType=tty\nUser=1000"),
            None
        );
        assert_eq!(
            parse_graphical_session_uid("Active=yes\nRemote=yes\nType=x11\nUser=1000"),
            None
        );
    }
}
