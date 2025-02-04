use crate::assets::{Asset, CssAssets, Kind};
use crate::cache::Cache;
use crate::db::Database;
use crate::errors::Error;
use crate::highlight::Highlighter;
use axum::extract::{DefaultBodyLimit, FromRef, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::Key;
use highlight::Theme;
use http::header::{
    CONTENT_SECURITY_POLICY, REFERRER_POLICY, SERVER, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    X_XSS_PROTECTION,
};
use http::{header, HeaderMap};
use std::num::NonZeroU32;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use url::Url;

mod assets;
mod cache;
mod crypto;
mod db;
mod env;
mod errors;
mod highlight;
mod id;
mod pages;
pub(crate) mod routes;
#[cfg(test)]
mod test_helpers;

static PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");

pub struct Page {
    version: &'static str,
    title: String,
    assets: Assets,
    base_url: Option<Url>,
}

pub struct Assets {
    favicon: Asset,
    css: CssAssets,
    index_js: Asset,
    paste_js: Asset,
}

#[derive(Clone)]
pub struct AppState {
    db: Database,
    cache: Cache,
    key: Key,
    max_expiration: Option<NonZeroU32>,
    page: Arc<Page>,
    highlighter: Arc<Highlighter>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

async fn security_headers_layer(req: Request, next: Next) -> impl IntoResponse {
    const SECURITY_HEADERS: [(HeaderName, HeaderValue); 7] = [

        (SERVER, HeaderValue::from_static(PACKAGE_NAME)),
        (CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; script-src 'self'; img-src 'self' data: ; style-src 'self' data: ; font-src 'self' data: ; object-src 'none' ; base-uri 'none' ; frame-ancestors 'none' ; form-action 'self' ;")),
        (REFERRER_POLICY, HeaderValue::from_static("same-origin")),
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN")),
        (HeaderName::from_static("x-permitted-cross-domain-policies"), HeaderValue::from_static("none")),
        (X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block")),
    ];

    (SECURITY_HEADERS, next.run(req).await)
}

impl Assets {
    fn new(theme: Theme) -> Self {
        Self {
            favicon: Asset::new(
                "favicon.ico",
                mime::IMAGE_PNG,
                include_bytes!("../assets/favicon.png").to_vec(),
            ),
            css: CssAssets::new(theme),
            index_js: Asset::new_hashed(
                "index",
                Kind::Js,
                include_bytes!("javascript/index.js").to_vec(),
            ),
            paste_js: Asset::new_hashed(
                "paste",
                Kind::Js,
                include_bytes!("javascript/paste.js").to_vec(),
            ),
        }
    }
}

impl Page {
    /// Create new page meta data from generated  `assets`, `title` and optional `base_url`.
    fn new(assets: Assets, title: String, base_url: Option<Url>) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            title,
            assets,
            base_url,
        }
    }

    /// Get base URL set in constructor or fall back to the user agent's `Host` header field.
    fn base_url_or_from(&self, headers: &HeaderMap) -> Result<Url, Error> {
        self.base_url.clone().map_or_else(
            || {
                let host = headers
                    .get(header::HOST)
                    .ok_or_else(|| Error::NoHost)?
                    .to_str()
                    .map_err(|_| Error::IllegalCharacters)?;

                Ok::<_, Error>(Url::parse(&format!("https://{host}"))?)
            },
            Ok,
        )
    }
}

async fn handle_service_errors(state: State<AppState>, req: Request, next: Next) -> Response {
    let response = next.run(req).await;

    match response.status() {
        StatusCode::PAYLOAD_TOO_LARGE => (
            StatusCode::PAYLOAD_TOO_LARGE,
            pages::Error::new("payload exceeded limit".to_string(), state.page.clone()),
        )
            .into_response(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            pages::Error::new("unsupported media type".to_string(), state.page.clone()),
        )
            .into_response(),
        _ => response,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("received signal, exiting ...");
}

async fn favicon(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.favicon.clone()
}

async fn style_css(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.css.style.clone()
}

async fn dark_css(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.css.dark.clone()
}

async fn light_css(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.css.light.clone()
}

async fn index_js(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.index_js.clone()
}

async fn paste_js(State(state): State<AppState>) -> impl IntoResponse {
    state.page.assets.paste_js.clone()
}

async fn serve(
    listener: TcpListener,
    state: AppState,
    timeout: Duration,
    max_body_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = routes::routes()
        .route(state.page.assets.favicon.route(), get(favicon))
        .route(state.page.assets.css.style.route(), get(style_css))
        .route(state.page.assets.css.dark.route(), get(dark_css))
        .route(state.page.assets.css.light.route(), get(light_css))
        .route(state.page.assets.index_js.route(), get(index_js))
        .route(state.page.assets.paste_js.route(), get(paste_js))
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(max_body_size))
                .layer(CompressionLayer::new())
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::new(timeout))
                .layer(from_fn_with_state(state.clone(), handle_service_errors))
                .layer(from_fn(security_headers_layer)),
        );

    axum::serve(listener, app.with_state(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cache_size = env::cache_size()?;
    let method = env::database_method()?;
    let key = env::signing_key()?;
    let addr = env::addr()?;
    let max_body_size = env::max_body_size()?;
    let base_url = env::base_url()?;
    let timeout = env::http_timeout()?;
    let max_expiration = env::max_paste_expiration()?;
    let theme = env::theme()?;
    let title = env::title();

    let cache = Cache::new(cache_size);
    let db = Database::new(method)?;

    tracing::debug!("serving on {addr}");
    tracing::debug!("caching {cache_size} paste highlights");
    tracing::debug!("restricting maximum body size to {max_body_size} bytes");
    tracing::debug!("enforcing a http timeout of {timeout:#?}");
    tracing::debug!("maximum expiration time of {max_expiration:?} seconds");

    let assets = Assets::new(theme);
    let page = Page::new(assets, title, base_url);
    let state = AppState {
        db,
        cache,
        key,
        max_expiration,
        page: Arc::new(page),
        highlighter: Arc::new(Highlighter::default()),
    };

    let listener = TcpListener::bind(&addr).await?;
    serve(listener, state, timeout, max_body_size).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}
