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
//! It is read-only. Standing up or resetting a network stays with the planner
//! and the operator's own hands, because those steps touch key material and a
//! browser is the wrong place to be holding any.
//!
//! ```text
//! activechain-operator-console [--port 8787] [--home <dir>]
//! ```

use activechain_network_planner::{NetworkManifest, fleet, plan_fleet, preflight};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Console {
    home: PathBuf,
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

    let console = Console { home };
    let router = Router::new()
        .route("/", get(page))
        .route("/api/fleet", get(fleet_json))
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

/// Compiles manifests without applying them, so an operator can see what a plan
/// would be. Unused by the read-only routes today; kept because the planner is
/// the console's reason for existing and the next surface it should grow.
#[allow(dead_code)]
fn preview(manifests: &[NetworkManifest], home: &std::path::Path) -> Result<String, String> {
    let plans = plan_fleet(manifests).map_err(|error| format!("{error:?}"))?;
    let assessments: Vec<_> = plans
        .iter()
        .map(|plan| {
            let root = home.join("activechain-deploy").join(&plan.name);
            preflight::assess(plan, &root)
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "plans": plans,
        "blocking": assessments
            .iter()
            .map(|assessment| assessment.blocking().len())
            .collect::<Vec<_>>(),
    }))
    .map_err(|error| error.to_string())
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

    /// Read-only means read-only: no route may mutate a deployment.
    #[test]
    fn the_console_exposes_no_mutating_route() {
        let code = serving_code();
        for verb in ["post(", "put(", "delete(", "patch("] {
            assert!(!code.contains(verb), "the console must stay read-only; found a {verb} route");
        }
    }
}
