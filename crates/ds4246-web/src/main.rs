//! DS4246 web dashboard (Phase 1, read-only).

mod auth;
mod config;
mod state;
mod views;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Form, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use crate::auth::{cookie_value, Login, COOKIE};
use crate::config::Config;
use crate::state::{AppState, Mode, Shared};

const CSS: &str = include_str!("../assets/app.css");
const JS: &str = include_str!("../assets/app.js");

#[derive(Parser)]
#[command(version, about = "DS4246 SES dashboard (read-only, Phase 1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Config file (TOML).
    #[arg(long, short, default_value = "/etc/ds4246-web/config.toml")]
    config: PathBuf,
    /// Override the bind address from the config.
    #[arg(long)]
    bind: Option<std::net::SocketAddr>,
    /// Serve saved dump directories instead of live hardware.
    #[arg(long, num_args = 1..)]
    replay: Vec<PathBuf>,
    /// Serve built-in synthetic data (no hardware).
    #[arg(long)]
    demo: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Prompt for a password and print its argon2 hash for the config file.
    HashPassword {
        /// Read the password from the first line of stdin instead of the terminal.
        #[arg(long)]
        stdin: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(Cmd::HashPassword { stdin }) = cli.cmd {
        let pw = if stdin {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        } else {
            let pw = rpassword::prompt_password("New dashboard password: ")?;
            if rpassword::prompt_password("Repeat: ")? != pw {
                bail!("passwords differ");
            }
            pw
        };
        if pw.len() < 8 {
            bail!("use at least 8 characters");
        }
        println!("password_hash = \"{}\"", auth::hash_password(&pw)?);
        return Ok(());
    }

    let mut cfg = Config::load(&cli.config)?;
    if let Some(b) = cli.bind {
        cfg.bind = b;
        cfg.validate()?;
    }
    let mode = match (cli.demo, cli.replay.is_empty()) {
        (true, _) => Mode::Demo,
        (false, false) => Mode::Replay(cli.replay),
        _ => Mode::Live,
    };
    if matches!(mode, Mode::Live) && unsafe { libc::geteuid() } != 0 {
        eprintln!("warning: not running as root; SG_IO on /dev/sg* will likely fail");
    }
    let bind = cfg.bind;
    let state: Shared = Arc::new(AppState::new(cfg, mode));
    tokio::spawn(state::poller(state.clone()));

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    eprintln!("ds4246-web listening on http://{bind}");
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn router(state: Shared) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/frag/dashboard", get(frag_dashboard))
        .route("/frag/elements", get(frag_elements))
        .route("/frag/raw", get(frag_raw))
        .route("/api/snapshot", get(api_snapshot))
        .route("/raw/{device}/{page}", get(raw_page))
        .route("/action/rescan", post(rescan))
        .route("/action/dump", post(dump))
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_login));
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/static/app.css", get(|| async { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS) }))
        .route("/static/app.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], JS) }))
        .merge(protected)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'");
    set(h, "x-frame-options", "DENY");
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(h, "cache-control", "no-store");
    res
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers.get(header::COOKIE)?.to_str().ok(), COOKIE).map(str::to_string)
}

async fn require_login(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let ok = session_token(req.headers()).is_some_and(|t| st.auth.check(&t));
    if !ok {
        let path = req.uri().path();
        return if path == "/" { Redirect::to("/login").into_response() } else { StatusCode::UNAUTHORIZED.into_response() };
    }
    // Simple CSRF guard on top of SameSite=Strict: state-changing requests
    // must carry a header a cross-site form cannot set.
    if req.method() == Method::POST && req.uri().path() != "/logout" && req.headers().get("x-ds4246").is_none() {
        return (StatusCode::FORBIDDEN, "missing x-ds4246 header").into_response();
    }
    next.run(req).await
}

async fn login_page() -> Html<String> {
    Html(views::login(None).into_string())
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login(State(st): State<Shared>, Form(f): Form<LoginForm>) -> Response {
    let s = st.clone();
    let res = tokio::task::spawn_blocking(move || s.auth.login(&f.password)).await;
    match res {
        Ok(Login::Ok(token)) => {
            let cookie = format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", st.auth.ttl().as_secs());
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Ok(Login::Locked) => (StatusCode::TOO_MANY_REQUESTS, Html(views::login(Some("Too many failed attempts; locked for 5 minutes.")).into_string())).into_response(),
        _ => {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            (StatusCode::UNAUTHORIZED, Html(views::login(Some("Wrong password.")).into_string())).into_response()
        }
    }
}

async fn logout(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(t) = session_token(&headers) {
        st.auth.logout(&t);
    }
    let clear = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, clear)], Redirect::to("/login")).into_response()
}

async fn index(State(st): State<Shared>) -> Html<String> {
    Html(views::shell(st.cfg.poll_secs, st.mode.banner()).into_string())
}

async fn frag_dashboard(State(st): State<Shared>) -> Html<String> {
    Html(views::dashboard(&st.data.read().unwrap()).into_string())
}

async fn frag_elements(State(st): State<Shared>) -> Html<String> {
    Html(views::elements(&st.data.read().unwrap()).into_string())
}

async fn frag_raw(State(st): State<Shared>) -> Html<String> {
    Html(views::raw(&st.data.read().unwrap()).into_string())
}

async fn api_snapshot(State(st): State<Shared>) -> Response {
    match &st.data.read().unwrap().snapshot {
        Some(s) => Json(s).into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn raw_page(State(st): State<Shared>, Path((device, page)): Path<(String, String)>) -> Response {
    let Some(code) = page.strip_suffix(".bin").and_then(|h| u8::from_str_radix(h, 16).ok()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let data = st.data.read().unwrap();
    let Some(bytes) = data.merged.iter().find(|r| r.device == device).and_then(|r| r.page(code)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let name = format!("attachment; filename=\"{device}_page_{code:02x}.bin\"");
    let mut res = Response::new(Body::from(bytes.to_vec()));
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    if let Ok(v) = HeaderValue::from_str(&name) {
        res.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    res
}

async fn rescan(State(st): State<Shared>) -> Html<String> {
    let s = st.clone();
    let res = tokio::task::spawn_blocking(move || s.refresh(true)).await;
    Html(match res {
        Ok(Ok(())) => views::message(true, "Full re-read done."),
        Ok(Err(e)) => views::message(false, &format!("Re-read failed: {e:#}")),
        Err(e) => views::message(false, &format!("Re-read task failed: {e}")),
    }
    .into_string())
}

async fn dump(State(st): State<Shared>) -> Html<String> {
    let s = st.clone();
    let res = tokio::task::spawn_blocking(move || s.save_dump()).await;
    Html(match res {
        Ok(Ok(dirs)) => views::message(true, &format!("Saved: {}", dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "))),
        Ok(Err(e)) => views::message(false, &format!("Dump failed: {e:#}")),
        Err(e) => views::message(false, &format!("Dump task failed: {e}")),
    }
    .into_string())
}
