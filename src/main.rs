//! The producer: enumerate Valve's master list, filter the flood, publish an artifact.
//!
//! Runs in two modes and needs no configuration in the common case:
//!
//! - `STEAM_API_KEY` in the environment â†’ straight to Valve, parallel, ~2 minutes. What Actions does.
//! - otherwise â†’ through the relay (`VAPOUR_RELAY`, defaulting to ours), sequential and paced, so a
//!   local run never needs the key.
//!
//! ```text
//! cargo run -p vapour-crawler -- --out servers.json.gz
//! ```

mod cluster;
mod steam;

use std::io::Write;

use cluster::{ClusterIndex, ReasonKind, Verdict};
use steam::{Enumerated, GameServer, Sweep, Transport};

const DEFAULT_RELAY: &str = "https://dayz-vapour-relay.chrisplayer.workers.dev";

/// One row as published: the server, and the verdict that follows it.
#[derive(serde::Serialize)]
struct Published {
    server: GameServer,
    verdict: Verdict,
    reasons: Vec<String>,
}

#[derive(serde::Serialize)]
struct Counts {
    listings: usize,
    distinct_names: usize,
    distinct_ips: usize,
    clean: usize,
    /// Shown with a badge.
    suspected: usize,
    /// Kept out of the list, with the reason carried per row for anyone who asks.
    hidden: usize,
}

#[derive(serde::Serialize)]
struct SweepStats {
    requests: usize,
    failed: usize,
    unresolved: usize,
    /// Empty answers on the first attempt â€” the signature of Valve throttling a busy client.
    empty_first: usize,
    /// Queries that were still empty after retrying: either a genuinely empty bucket or a real miss.
    empty_stubborn: usize,
    maps: usize,
    /// True when every query completed and no bucket was left at the cap.
    complete: bool,
}

#[derive(serde::Serialize)]
struct Artifact {
    generated_at: u64,
    source: String,
    sweep: SweepStats,
    counts: Counts,
    servers: Vec<Published>,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let max_requests = args
        .iter()
        .position(|a| a == "--max-requests")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(12_000);
    let publish = args.iter().any(|a| a == "--publish");

    // Re-publish an artifact that already exists, without sweeping again. Covers the case where the
    // enumeration succeeded but the upload did not, and lets the relay be tested for free.
    if let Some(i) = args.iter().position(|a| a == "--publish-only") {
        let Some(path) = args.get(i + 1) else {
            eprintln!("--publish-only needs a path");
            std::process::exit(2);
        };
        let bytes = std::fs::read(path).unwrap_or_else(|error| {
            eprintln!("could not read {path}: {error}");
            std::process::exit(2);
        });
        publish_artifact(&bytes).await;
        return;
    }

    // Read the cut-offs before spending a single query: a misconfigured run should fail here, not
    // after twenty minutes of enumeration.
    let thresholds = match cluster::Thresholds::from_env() {
        Ok(thresholds) => thresholds,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    let transport = match std::env::var("STEAM_API_KEY") {
        Ok(key) if !key.trim().is_empty() => Transport::Direct(key.trim().to_string()),
        _ => Transport::Relay(
            std::env::var("VAPOUR_RELAY").unwrap_or_else(|_| DEFAULT_RELAY.to_string()),
        ),
    };
    println!("transport  : {}", transport.label());

    let started = std::time::Instant::now();
    let mut sweep = match Sweep::new(&transport) {
        Ok(sweep) => sweep,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    sweep.max_requests = max_requests;

    let found = match sweep.run().await {
        Ok(found) => found,
        Err(error) => {
            eprintln!("sweep failed: {error}");
            std::process::exit(2);
        }
    };
    println!("elapsed    : {:.1} s", started.elapsed().as_secs_f32());

    report(&found, thresholds);

    let index = ClusterIndex::build(&found.servers, thresholds);
    let mut servers = Vec::with_capacity(found.servers.len());
    let mut clean = 0usize;
    let mut suspected = 0usize;
    let mut hidden = 0usize;

    // Listings per address: the thing the filter keys on, needed here for the audit.
    let mut per_ip: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for server in &found.servers {
        *per_ip.entry(steam::ip_of(&server.addr)).or_insert(0) += 1;
    }
    let flood: std::collections::HashSet<&str> = per_ip
        .iter()
        .filter(|(_, count)| **count >= thresholds.mega_host_listings)
        .map(|(ip, _)| *ip)
        .collect();

    // Why rows were hidden, split by whether the row's own address is a flood address. A row on a
    // 2,000-listing address is farm output; a row on an ordinary address could be somebody's real
    // server, and those are the only hidden rows worth losing sleep over.
    let mut by_kind: std::collections::BTreeMap<ReasonKind, usize> =
        std::collections::BTreeMap::new();
    let mut ordinary: std::collections::BTreeMap<ReasonKind, usize> =
        std::collections::BTreeMap::new();
    let mut outcome: std::collections::HashMap<&str, (ReasonKind, bool)> =
        std::collections::HashMap::new();

    for server in &found.servers {
        let assessment = index.assess(server);
        let ip = steam::ip_of(&server.addr);
        outcome.entry(ip).or_insert((assessment.kind, assessment.hide));

        match assessment.verdict {
            Verdict::Clean => clean += 1,
            Verdict::Suspected | Verdict::Impossible => suspected += 1,
        }
        if assessment.hide {
            hidden += 1;
            *by_kind.entry(assessment.kind).or_insert(0) += 1;
            if !flood.contains(ip) {
                *ordinary.entry(assessment.kind).or_insert(0) += 1;
            }
            continue;
        }
        servers.push(Published {
            server: server.clone(),
            verdict: assessment.verdict,
            reasons: assessment.reasons,
        });
    }

    let names: std::collections::HashSet<&str> =
        found.servers.iter().map(|s| s.name.as_str()).collect();
    let ips = index.ip_count();

    // The number that decides whether this filter is honest. A name whose every row sits on a flood
    // address was invented by the farm; a name that also appears on an **ordinary** address had that
    // row hidden, and each of those is a server a player cannot find. Hidden rows are cheap, lost
    // names are expensive, and only the second kind is a real cost.
    let published_names: std::collections::HashSet<&str> =
        servers.iter().map(|p| p.server.name.as_str()).collect();
    let mut lost_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut lost_on_ordinary: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for server in &found.servers {
        let name = server.name.as_str();
        if published_names.contains(name) {
            continue;
        }
        lost_names.insert(name);
        if !flood.contains(steam::ip_of(&server.addr)) {
            lost_on_ordinary.insert(name);
        }
    }

    println!();
    println!("===== filter =====");
    println!("clean      : {clean}");
    println!("suspected  : {suspected}  (visible, badged)");
    println!("hidden     : {hidden}");
    for (kind, count) in &by_kind {
        let normal = ordinary.get(kind).copied().unwrap_or(0);
        println!(
            "  {:<26}: {count:>7}   {normal:>6} on ordinary addresses",
            kind.label()
        );
    }
    println!("published  : {} of {} listings", servers.len(), found.servers.len());
    println!(
        "names      : {} seen, {} published, {} never published",
        names.len(),
        published_names.len(),
        lost_names.len()
    );
    println!(
        "             {} of the lost names exist only on flood addresses; {} appear on an ordinary one",
        lost_names.len() - lost_on_ordinary.len(),
        lost_on_ordinary.len()
    );

    // The audit view. Hiding is concentrated on a couple of hundred addresses, so those are the ones
    // worth looking at by eye: a farm republishes a whole catalogue, while a community running a
    // dozen servers on one box has its own names and a modest count.
    let mut clusters: Vec<(&str, usize)> = per_ip.into_iter().collect();
    clusters.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    println!();
    println!("===== heaviest addresses =====");
    for (ip, count) in clusters.iter().take(15) {
        let (kind, hide) = outcome.get(ip).copied().unwrap_or((ReasonKind::None, false));
        let profile = index.profile_of(ip);
        let (names_here, borrowed) = match profile {
            Some(p) => (p.distinct_names, p.borrowed_names),
            None => (0, 0),
        };
        let share = (borrowed * 100).checked_div(names_here).unwrap_or(0);
        println!(
            "{ip:>15}  {count:>6} listings  {names_here:>6} names  {share:>3}% borrowed  {:<10} {}",
            if hide { "hidden" } else { "visible" },
            kind.label()
        );
    }
    println!(
        "{} addresses in total; {} of them publish a flood-sized number of listings",
        index.ip_count(),
        flood.len()
    );

    if let Some(path) = out {
        let artifact = Artifact {
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            source: match &transport {
                Transport::Direct(_) => "valve".to_string(),
                Transport::Relay(base) => base.clone(),
            },
            sweep: SweepStats {
                requests: found.requests,
                failed: found.failed,
                unresolved: found.unresolved,
                empty_first: found.empty_first,
                empty_stubborn: found.empty_stubborn,
                maps: found.maps.len(),
                complete: found.complete(),
            },
            counts: Counts {
                listings: found.servers.len(),
                distinct_names: names.len(),
                distinct_ips: ips,
                clean,
                suspected,
                hidden,
            },
            servers,
        };

        let json = match serde_json::to_vec(&artifact) {
            Ok(json) => json,
            Err(error) => {
                eprintln!("could not serialise the artifact: {error}");
                std::process::exit(2);
            }
        };
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        if encoder.write_all(&json).is_err() {
            eprintln!("could not compress the artifact");
            std::process::exit(2);
        }
        let bytes = match encoder.finish() {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("could not compress the artifact: {error}");
                std::process::exit(2);
            }
        };
        match std::fs::write(&path, &bytes) {
            Ok(()) => println!(
                "wrote      : {path}  ({:.1} KB raw, {:.1} KB gzipped)",
                json.len() as f32 / 1024.0,
                bytes.len() as f32 / 1024.0
            ),
            Err(error) => {
                eprintln!("could not write {path}: {error}");
                std::process::exit(2);
            }
        }

        if publish {
            publish_artifact(&bytes).await;
        }
    }
}

/// Hand the artifact to the relay, which stores it in Cloudflare KV for the launcher to read.
///
/// Deliberately a plain `PUT` of bytes: the relay never parses it, which is the whole reason this
/// works on a free Cloudflare plan where parsing megabytes would blow the 10 ms CPU budget.
///
/// The upload is token-gated with a **separate** token, not the Steam key. Reusing the key across
/// purposes would put a Valve credential on the wire for something that has nothing to do with Valve.
async fn publish_artifact(bytes: &[u8]) {
    let base = std::env::var("VAPOUR_RELAY")
        .unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let token = match std::env::var("VAPOUR_TOKEN") {
        Ok(token) if !token.trim().is_empty() => token,
        _ => {
            eprintln!("--publish needs VAPOUR_TOKEN in the environment");
            std::process::exit(2);
        }
    };
    let url = format!("{}/artifact/servers", base.trim_end_matches('/'));

    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("could not build an upload client: {error}");
            std::process::exit(2);
        }
    };

    match client
        .put(&url)
        .header("x-vapour-token", token.trim())
        .header("content-type", "application/gzip")
        .body(bytes.to_vec())
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await.unwrap_or_default();
            println!("published  : {url}  ({})", body.trim());
        }
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eprintln!("publish failed: HTTP {status}: {body}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("publish failed: {error}");
            std::process::exit(2);
        }
    }
}

fn report(found: &Enumerated, thresholds: cluster::Thresholds) {
    println!();
    println!("===== sweep =====");
    println!(
        "requests   : {}  ({} failed, {} unresolved)",
        found.requests, found.failed, found.unresolved
    );
    println!("complete   : {}", found.complete());
    println!(
        "empty pages: {} first attempt, {} still empty after retries",
        found.empty_first, found.empty_stubborn
    );
    println!("maps       : {}", found.maps.len());
    println!("listings   : {}", found.servers.len());

    let names: std::collections::HashSet<&str> =
        found.servers.iter().map(|s| s.name.as_str()).collect();
    let mut per_ip: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for server in &found.servers {
        *per_ip.entry(steam::ip_of(&server.addr)).or_insert(0) += 1;
    }
    println!("distinct names: {}", names.len());
    println!("distinct IPs  : {}", per_ip.len());

    // Bands are expressed relative to the flood cut-off, so the log does not print it.
    let cut = thresholds.mega_host_listings;
    let mut bands = [0usize; 6];
    for count in per_ip.values() {
        let slot = match *count {
            0 | 1 => 0,
            2..=5 => 1,
            6..=20 => 2,
            n if n < cut => 3,
            n if n < cut * 2 => 4,
            _ => 5,
        };
        bands[slot] += 1;
    }
    println!(
        "IPs by listings: 1={} 2-5={} 6-20={} 21..cut={} cut..2cut={} 2cut+={}",
        bands[0], bands[1], bands[2], bands[3], bands[4], bands[5]
    );

    let mut clusters: Vec<(&str, usize)> = per_ip.into_iter().collect();
    clusters.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    if let Some((ip, count)) = clusters.first() {
        println!("largest host  : {ip} with {count} listings");
    }
}

