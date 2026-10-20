//! Password login with in-memory sessions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

pub const COOKIE: &str = "ds4246_session";
const MAX_FAILS: u32 = 10;
const LOCKOUT: Duration = Duration::from_secs(300);

pub struct Auth {
    hash: String,
    ttl: Duration,
    sessions: Mutex<HashMap<String, Instant>>,
    fails: Mutex<(u32, Option<Instant>)>,
}

pub enum Login {
    Ok(String),
    Wrong,
    Locked,
}

impl Auth {
    pub fn new(hash: String, ttl: Duration) -> Self {
        Self { hash, ttl, sessions: Mutex::default(), fails: Mutex::default() }
    }

    /// Blocking (argon2 is deliberately slow); call from spawn_blocking.
    pub fn login(&self, password: &str) -> Login {
        {
            let mut f = self.fails.lock().unwrap();
            if let Some(until) = f.1 {
                if Instant::now() < until {
                    return Login::Locked;
                }
                *f = (0, None);
            }
        }
        let ok = PasswordHash::new(&self.hash).map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok()).unwrap_or(false);
        if !ok {
            let mut f = self.fails.lock().unwrap();
            f.0 += 1;
            if f.0 >= MAX_FAILS {
                f.1 = Some(Instant::now() + LOCKOUT);
            }
            return Login::Wrong;
        }
        *self.fails.lock().unwrap() = (0, None);
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, exp| *exp > now);
        s.insert(token.clone(), now + self.ttl);
        Login::Ok(token)
    }

    pub fn check(&self, token: &str) -> bool {
        let s = self.sessions.lock().unwrap();
        s.get(token).is_some_and(|exp| *exp > Instant::now())
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(pw.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("{e}"))?.to_string())
}

pub fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_flow() {
        let auth = Auth::new(hash_password("hunter2").unwrap(), Duration::from_secs(60));
        assert!(matches!(auth.login("nope"), Login::Wrong));
        let Login::Ok(t) = auth.login("hunter2") else { panic!() };
        assert!(auth.check(&t));
        assert!(!auth.check("deadbeef"));
        auth.logout(&t);
        assert!(!auth.check(&t));
        assert_eq!(cookie_value(Some("a=1; ds4246_session=abc"), COOKIE), Some("abc"));
    }
}
