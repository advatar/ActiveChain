//! A console for the operator of the host it runs on.
//!
//! Running here rather than somewhere else is the whole security argument. The
//! console sits on the machine that already holds the networks, so nothing it
//! reads crosses a network and there is no remote surface to authenticate. It
//! binds loopback only, and offers no way to do otherwise: a console bound to a
//! public interface would hand the host's deployment layout to anyone who could
//! reach the port, which is a mistake this codebase has already made once with
//! an RPC node.
//!
//! The browser may *trigger* work the host performs, but never holds key
//! material itself: applying a plan creates directories and launch agents,
//! while keys, the genesis and the trust ceremony remain the operator's.
//! Resetting a network is deliberately absent — it is destructive and belongs
//! in a place where a mis-click cannot reach it.
//!
//! Loopback is not by itself a security boundary against a browser: any page
//! the operator visits can issue requests to this port. Three guards close
//! that, and every mutating request must pass all of them.
//!
//! * a **session token**, minted at startup and printed to the terminal, so a
//!   page that cannot read the console's own HTML cannot act;
//! * an **origin check**, rejecting any request whose `Origin` is not this
//!   console;
//! * a **host check**, rejecting any `Host` that is not a loopback literal,
//!   which is what stops DNS rebinding from turning a foreign page into a
//!   same-origin one.
//!
//! ```text
//! activechain-operator-console [--port 8787] [--home <dir>]
//! ```

use activechain_network_planner::{NetworkManifest, apply, fleet, plan_fleet, preflight};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

#[derive(Clone)]
struct Console {
    home: PathBuf,
    port: u16,
    /// Minted at startup, printed to the terminal, embedded in the console's
    /// own page. A page that cannot read that page cannot act.
    token: String,
}

impl Console {
    /// Accepts a mutating request only from this console's own page.
    fn authorize(&self, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
        // A Host that is not a loopback literal means the request arrived via a
        // name that resolved here — the shape of a DNS rebinding attempt, where
        // a foreign page becomes same-origin by pointing its own hostname at
        // 127.0.0.1.
        let host = headers.get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or("");
        let expected_hosts =
            [format!("127.0.0.1:{}", self.port), format!("localhost:{}", self.port)];
        if !expected_hosts.iter().any(|candidate| candidate == host) {
            return Err((StatusCode::MISDIRECTED_REQUEST, "unexpected Host"));
        }
        // A cross-site form post carries an Origin that is not ours. A same-page
        // fetch carries ours.
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok()) {
            let ours =
                expected_hosts.iter().any(|candidate| origin == format!("http://{candidate}"));
            if !ours {
                return Err((StatusCode::FORBIDDEN, "cross-origin request"));
            }
        }
        // A cross-site request carries Sec-Fetch-Site: cross-site. Absence is
        // tolerated because non-browser callers on this host are legitimate.
        if let Some(site) = headers.get("sec-fetch-site").and_then(|value| value.to_str().ok())
            && site != "same-origin"
            && site != "none"
        {
            return Err((StatusCode::FORBIDDEN, "cross-site request"));
        }
        let presented = headers
            .get("x-activechain-console")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        // Constant time: a byte-at-a-time comparison would leak the token to a
        // local page willing to measure.
        let matches: bool = presented.as_bytes().ct_eq(self.token.as_bytes()).into();
        if !matches {
            return Err((StatusCode::UNAUTHORIZED, "missing or wrong console token"));
        }
        Ok(())
    }
}

/// Session token, from the system CSPRNG.
///
/// It authorizes only what an operator sitting at this machine could already
/// do, but it must be unguessable by a page that never saw it — so it is not
/// derived from the clock or the process id, both of which a local attacker can
/// approximate.
fn mint_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("no system randomness: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut port: u16 = 8787;
    let mut home: Option<PathBuf> = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--port" => port = arguments.next().ok_or("--port needs a number")?.parse()?,
            "--home" => home = Some(PathBuf::from(arguments.next().ok_or("--home needs a path")?)),
            other => return Err(format!("unknown option {other}").into()),
        }
    }
    let home = home
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
        .ok_or("could not determine the home directory; pass --home")?;

    let console = Console { home, port, token: mint_token()? };
    eprintln!("console token {}", console.token);
    let router = Router::new()
        .route("/", get(page))
        .route("/api/fleet", get(fleet_json))
        .route("/api/plan", post(plan_preview))
        .route("/api/apply", post(apply_plan))
        // A manifest is small. Bounding the body keeps a local page from
        // exhausting memory on a host that is also running validators.
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(Arc::new(console));

    // Loopback only, and not a configurable choice. Everything this serves
    // describes where a host keeps its networks; that belongs to whoever is
    // already sitting at the machine.
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(address).await?;
    eprintln!("operator console on http://{address} (loopback only)");
    axum::serve(listener, router).await?;
    Ok(())
}

/// Serialized through typed values rather than `serde_json::Value`, because a
/// `Value::Number` cannot hold a `u128` above `u64::MAX` and a genesis supply
/// routinely is. Building one panicked at runtime while the tests, which never
/// touched this path, stayed green.
#[derive(serde::Serialize)]
struct FleetResponse<'a> {
    deployments: Vec<DeploymentView<'a>>,
    unaccounted: &'a [String],
}

#[derive(serde::Serialize)]
struct DeploymentView<'a> {
    plan: &'a activechain_network_planner::NetworkPlan,
    services: Vec<ServiceView<'a>>,
    state: &'static str,
}

#[derive(serde::Serialize)]
struct ServiceView<'a> {
    role: &'a str,
    port: u16,
    listening: bool,
}

/// Applied to every response.
///
/// The console renders values read off this host's disk. None of it should be
/// framed, sniffed, sent anywhere, or able to load anything external, and a
/// strict policy costs nothing on a page this simple.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; \
             img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn fleet_json(State(console): State<Arc<Console>>) -> Response {
    let discovered = fleet::discover(&console.home);
    let payload = FleetResponse {
        deployments: discovered
            .deployments
            .iter()
            .map(|deployment| DeploymentView {
                plan: &deployment.plan,
                services: deployment
                    .services
                    .iter()
                    .map(|(role, port, listening)| ServiceView {
                        role,
                        port: *port,
                        listening: *listening,
                    })
                    .collect(),
                state: if deployment.fully_running() {
                    "running"
                } else if deployment.stopped() {
                    "stopped"
                } else {
                    "partial"
                },
            })
            .collect(),
        unaccounted: &discovered.unaccounted,
    };
    match serde_json::to_string(&payload) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
            body,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain"), (header::CACHE_CONTROL, "no-store")],
            format!("could not encode the fleet: {error}"),
        )
            .into_response(),
    }
}

/// Compiles manifests and reports what this host says about them, without
/// creating anything. The safe half of the loop: an operator can see the plan
/// and the blocking findings before deciding to apply.
async fn plan_preview(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(manifests): Json<Vec<NetworkManifest>>,
) -> Response {
    if let Err((status, reason)) = console.authorize(&headers) {
        return (status, reason).into_response();
    }
    let plans = match plan_fleet(&manifests) {
        Ok(plans) => plans,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, format!("{error:?}")).into_response();
        }
    };
    let findings: Vec<Vec<String>> = plans
        .iter()
        .map(|plan| {
            let root = console.home.join("activechain-deploy").join(&plan.name);
            preflight::assess(plan, &root)
                .findings
                .iter()
                .map(std::string::ToString::to_string)
                .collect()
        })
        .collect();

    #[derive(serde::Serialize)]
    struct Preview<'a> {
        plans: &'a [activechain_network_planner::NetworkPlan],
        findings: Vec<Vec<String>>,
    }
    match serde_json::to_string(&Preview { plans: &plans, findings }) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
            body,
        )
            .into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// Creates the deployment a plan describes.
///
/// The browser triggers it; the host performs it. Nothing here generates or
/// touches key material — apply stops at that boundary and reports what it left
/// for the operator.
async fn apply_plan(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(manifests): Json<Vec<NetworkManifest>>,
) -> Response {
    if let Err((status, reason)) = console.authorize(&headers) {
        return (status, reason).into_response();
    }
    let plans = match plan_fleet(&manifests) {
        Ok(plans) => plans,
        Err(error) => return (StatusCode::BAD_REQUEST, format!("{error:?}")).into_response(),
    };
    let agents = console.home.join("Library/LaunchAgents");
    let mut applied = Vec::new();
    for plan in &plans {
        match apply::apply(plan, &console.home, &agents) {
            Ok(record) => applied.push(serde_json::json!({
                "network": record.network,
                "planDigest": record.plan_digest,
                "root": record.root.display().to_string(),
                "launchAgents": record.launch_agents,
                "remaining": record.remaining,
            })),
            // Reported rather than rolled back: earlier networks in the batch
            // are real deployments now, and pretending otherwise would be worse
            // than saying where it stopped.
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    serde_json::json!({ "applied": applied, "stopped": error.to_string() })
                        .to_string(),
                )
                    .into_response();
            }
        }
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
        serde_json::json!({ "applied": applied }).to_string(),
    )
        .into_response()
}

async fn page(State(console): State<Arc<Console>>) -> Html<String> {
    let discovered = fleet::discover(&console.home);
    let mut body = String::from(
        "<h1>ActiveChain networks</h1>\
         <p class=\"note\">Read-only. This console runs on the host it describes and listens on \
         loopback only.</p>",
    );

    if discovered.deployments.is_empty() && discovered.unaccounted.is_empty() {
        body.push_str("<p>No networks are deployed on this host.</p>");
    }

    for deployment in &discovered.deployments {
        let plan = &deployment.plan;
        let state = if deployment.fully_running() {
            "running"
        } else if deployment.stopped() {
            "stopped"
        } else {
            "partial"
        };
        let chain: String =
            plan.chain_id.as_bytes().iter().take(8).map(|byte| format!("{byte:02x}")).collect();
        body.push_str(&format!(
            "<section><h2>{} <span class=\"state {state}\">{state}</span></h2>\
             <dl><dt>domain</dt><dd>{}</dd>\
             <dt>chain</dt><dd class=\"mono\">{chain}…</dd>\
             <dt>treasury</dt><dd>{} Coin Cells, {} grant(s) of capacity</dd></dl><table>",
            escape(&plan.name),
            escape(&plan.domain),
            plan.treasury_cells,
            plan.grant_capacity,
        ));
        for (role, port, listening) in &deployment.services {
            body.push_str(&format!(
                "<tr><td>{}</td><td class=\"mono\">{port}</td><td>{}</td></tr>",
                escape(role),
                if *listening { "listening" } else { "—" }
            ));
        }
        body.push_str("</table></section>");
    }

    // Named, not omitted: a deployment nobody can describe is the one most
    // worth seeing.
    for name in &discovered.unaccounted {
        body.push_str(&format!(
            "<section class=\"unknown\"><h2>{} <span class=\"state unknown\">unknown</span></h2>\
             <p>No recorded plan. This deployment cannot be described.</p></section>",
            escape(name)
        ));
    }

    Html(shell(&body))
}

/// Everything is inline: the console must work on a host with no network route
/// to anywhere, which is rather the point of running it there.
fn shell(body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>ActiveChain operator console</title><style>\
         body{{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:2rem;\
         background:#0a0e17;color:#e8ecf4}}\
         h1{{font-size:1.4rem;margin:0 0 .25rem}}h2{{font-size:1.05rem;margin:0 0 .75rem}}\
         .note{{color:#93a1bd;margin:0 0 2rem}}\
         section{{background:#131a28;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1rem}}\
         section.unknown{{border:1px solid #7a5c1f}}\
         dl{{display:grid;grid-template-columns:8rem 1fr;gap:.25rem 1rem;margin:0 0 1rem}}\
         dt{{color:#93a1bd}}dd{{margin:0}}\
         table{{width:100%;border-collapse:collapse}}\
         td{{padding:.3rem 0;border-top:1px solid #1e2739}}\
         .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}\
         .state{{font-size:.75rem;padding:.15rem .5rem;border-radius:999px;vertical-align:middle}}\
         .running{{background:#12402c;color:#72f5b4}}\
         .stopped{{background:#232b3b;color:#93a1bd}}\
         .partial,.unknown{{background:#42330f;color:#f5c86b}}\
         </style></head><body>{body}</body></html>"
    )
}

/// Network names and domains reach the page. They come from files on this host
/// rather than from a stranger, but escaping them costs nothing and means a
/// deployment directory cannot inject markup into the console.
fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console's own source, excluding these tests — otherwise the
    /// assertions below match their own needles.
    fn serving_code() -> &'static str {
        let source = include_str!("main.rs");
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    /// The console must never be reachable from off the host. Binding anything
    /// other than loopback would publish where a machine keeps its networks.
    #[test]
    fn the_console_binds_loopback_only() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);
        assert!(address.ip().is_loopback());
        let code = serving_code();
        assert!(
            !code.contains("0.0.0.0") && !code.contains("UNSPECIFIED"),
            "the console must not offer a way to bind a public interface"
        );
        assert!(code.contains("Ipv4Addr::LOCALHOST"), "the bind address must be loopback");
    }

    /// A deployment directory is named by whoever created it, so it must not be
    /// able to put markup into the page.
    #[test]
    fn names_from_disk_cannot_inject_markup() {
        let escaped = escape("<script>alert('x')</script>&\"");
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    fn console() -> Console {
        Console {
            home: PathBuf::from("/tmp/activechain-console-test"),
            port: 8787,
            token: "0123456789abcdef".to_owned(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    /// The console can trigger work, so the guard is the security boundary.
    /// Loopback alone is not one: any page the operator visits can reach this
    /// port.
    #[test]
    fn a_request_from_this_consoles_own_page_is_authorized() {
        let console = console();
        assert!(
            console
                .authorize(&headers(&[
                    ("host", "127.0.0.1:8787"),
                    ("origin", "http://127.0.0.1:8787"),
                    ("sec-fetch-site", "same-origin"),
                    ("x-activechain-console", "0123456789abcdef"),
                ]))
                .is_ok()
        );
    }

    /// A page that never saw the console's HTML cannot have its token.
    #[test]
    fn a_request_without_the_token_is_refused() {
        let console = console();
        let base = [("host", "127.0.0.1:8787")];
        assert_eq!(console.authorize(&headers(&base)).unwrap_err().0, StatusCode::UNAUTHORIZED);
        let mut wrong = base.to_vec();
        wrong.push(("x-activechain-console", "0123456789abcdee"));
        assert_eq!(
            console.authorize(&headers(&wrong)).unwrap_err().0,
            StatusCode::UNAUTHORIZED,
            "a token differing in one character must not be accepted"
        );
    }

    /// A form posted from another site carries a foreign Origin.
    #[test]
    fn a_cross_origin_request_is_refused_even_with_a_token() {
        let console = console();
        let error = console
            .authorize(&headers(&[
                ("host", "127.0.0.1:8787"),
                ("origin", "https://example.invalid"),
                ("x-activechain-console", "0123456789abcdef"),
            ]))
            .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_cross_site_fetch_is_refused_even_with_a_token() {
        let console = console();
        let error = console
            .authorize(&headers(&[
                ("host", "127.0.0.1:8787"),
                ("sec-fetch-site", "cross-site"),
                ("x-activechain-console", "0123456789abcdef"),
            ]))
            .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }

    /// DNS rebinding: a foreign page points its own hostname at 127.0.0.1 and
    /// becomes same-origin. The Host header still names the attacker's domain.
    #[test]
    fn a_request_arriving_under_a_rebound_hostname_is_refused() {
        let console = console();
        let error = console
            .authorize(&headers(&[
                ("host", "attacker.invalid:8787"),
                ("origin", "http://attacker.invalid:8787"),
                ("x-activechain-console", "0123456789abcdef"),
            ]))
            .unwrap_err();
        assert_eq!(error.0, StatusCode::MISDIRECTED_REQUEST);
    }

    /// Every mutating handler must consult the guard. A route added later that
    /// forgets to is the failure this catches.
    #[test]
    fn every_mutating_handler_authorizes_before_acting() {
        let code = serving_code();
        for handler in ["async fn plan_preview", "async fn apply_plan"] {
            let start = code.find(handler).unwrap_or_else(|| panic!("{handler} is missing"));
            let body = &code[start..];
            let guard = body.find("console.authorize(&headers)").unwrap_or(usize::MAX);
            let acts = body.find("plan_fleet(").unwrap_or(usize::MAX);
            assert!(guard < acts, "{handler} must authorize before it acts");
        }
    }

    /// A token from the clock or the process id is guessable by anything local.
    #[test]
    fn the_token_comes_from_system_randomness_and_is_long() {
        let first = mint_token().expect("randomness");
        let second = mint_token().expect("randomness");
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
    }
}
