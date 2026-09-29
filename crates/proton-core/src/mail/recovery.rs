//! Optional unattended login recovery using a service-manager credential.
use super::{Client, LoginOptions};
use crate::error::{Error, Result};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use totp_rs::{Builder, Secret};
use zeroize::Zeroize;

#[derive(serde::Deserialize)]
struct Bootstrap {
    username: String,
    password: String,
    #[serde(default)]
    totp_secret: String,
    #[serde(default)]
    mailbox_password: Option<String>,
    #[serde(default)]
    app_version: Option<String>,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp_secret.zeroize();
        self.mailbox_password.zeroize();
    }
}

static LAST_LOGIN: Mutex<Option<Instant>> = Mutex::new(None);

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct RecoveryState {
    last_attempt: u64,
    blocked: bool,
}

fn read_state(path: &std::path::Path) -> Result<RecoveryState> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| Error::Session("invalid recovery state; refusing login".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RecoveryState::default()),
        Err(e) => Err(e.into()),
    }
}
fn write_state(path: &std::path::Path, state: &RecoveryState) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp-{}", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}
fn begin_attempt(path: &std::path::Path, now: u64) -> Result<()> {
    let state = read_state(path)?;
    if state.blocked {
        return Err(Error::Session("automatic login suspended after a Proton account-protection or authentication error; resolve the restriction before clearing the recovery state".into()));
    }
    if state.last_attempt != 0 && now.saturating_sub(state.last_attempt) < 600 {
        return Err(Error::Session(
            "automatic login rate-limited across restarts; retry after ten minutes".into(),
        ));
    }
    write_state(
        path,
        &RecoveryState {
            last_attempt: now,
            blocked: false,
        },
    )
}

impl Client {
    /// Resume normally, then recover an expired/revoked session if configured.
    /// Network and crypto failures do not trigger repeated account logins.
    pub async fn resume_automated(profile: &str) -> Result<Self> {
        match Self::resume(profile).await {
            Ok(c) => return Ok(c),
            Err(Error::Unauthorized) => {}
            Err(Error::Api(e)) if matches!(e.http_status, 401 | 403) => {}
            Err(e) => return Err(e),
        }
        let path = std::env::var_os("PROTON_BOOTSTRAP_FILE").ok_or(Error::Unauthorized)?;
        let state_path = std::env::var_os("PROTON_RECOVERY_STATE_FILE").ok_or_else(|| {
            Error::Session("unattended login requires a persistent recovery-state file".into())
        })?;
        let state_path = std::path::Path::new(&state_path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Session("invalid system clock".into()))?
            .as_secs();
        begin_attempt(state_path, now)?;
        let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
        let credentials: Bootstrap = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Session("invalid bootstrap credential JSON".into()))?;
        {
            let mut last = LAST_LOGIN
                .lock()
                .map_err(|_| Error::Session("recovery lock poisoned".into()))?;
            if last.is_some_and(|t| t.elapsed() < Duration::from_secs(600)) {
                return Err(Error::Session(
                    "automatic login rate-limited; retry after ten minutes".into(),
                ));
            }
            *last = Some(Instant::now());
        }
        let totp = if credentials.totp_secret.is_empty() {
            None
        } else {
            let secret = Secret::try_from_base32(&credentials.totp_secret)
                .map_err(|_| Error::Session("invalid TOTP configuration".into()))?;
            let generator = Builder::new()
                .with_secret(secret)
                .build()
                .map_err(|_| Error::Session("invalid TOTP configuration".into()))?;
            Some(generator.generate_current().to_string())
        };
        tracing::warn!("recovering Proton session using configured service credential");
        let result = Self::login(LoginOptions {
            username: credentials.username.clone(),
            password: credentials.password.clone(),
            totp,
            mailbox_password: credentials.mailbox_password.clone(),
            profile: profile.into(),
            base_url: None,
            app_version: credentials.app_version.clone(),
            user_agent: None,
            hv: None, // CAPTCHA requires a human; never weaken this check.
        })
        .await;
        match &result {
            Ok(_) => write_state(state_path, &RecoveryState::default())?,
            Err(Error::Http(_)) => {}
            Err(Error::Api(e)) if e.http_status == 429 || e.http_status >= 500 => {}
            Err(_) => write_state(
                state_path,
                &RecoveryState {
                    last_attempt: now,
                    blocked: true,
                },
            )?,
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_cooldown_and_provider_stop_survive_restart() {
        let path =
            std::env::temp_dir().join(format!("recovery-state-{}.json", rand::random::<u64>()));
        begin_attempt(&path, 1000).unwrap();
        assert!(begin_attempt(&path, 1001).is_err());
        begin_attempt(&path, 1600).unwrap();
        write_state(
            &path,
            &RecoveryState {
                last_attempt: 1600,
                blocked: true,
            },
        )
        .unwrap();
        assert!(begin_attempt(&path, 99999).is_err());
        write_state(&path, &RecoveryState::default()).unwrap();
        begin_attempt(&path, 99999).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
