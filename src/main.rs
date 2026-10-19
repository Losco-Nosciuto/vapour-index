//! The producer: enumerate Valve's master list, filter the flood, publish an artifact.
//!
//! Two ways to read the master list, picked by the environment:
//!
//! - `STEAM_API_KEY` set: straight to Valve, parallel. A complete sweep is a few minutes.
//! - otherwise: through the relay (`VAPOUR_RELAY`, defaulting to ours), which holds the key, so a
//!   local run never needs one.
//!
//! A page of 10,000 rows costs roughly 3.3 seconds from Valve, so what decides how long a sweep takes
//! is the number of buckets the distribution produces, not the number of servers in it.
//!
//! ```text
//! cargo run -- --out servers.json.gz
//! ```

mod a2s;
mod cluster;
mod steam;

use std::io::{Read, Write};

use futures::StreamExt;

use cluster::{ClusterIndex, ReasonKind, Verdict};
use steam::{Enumerated, GameServer, Sweep, Transport};

const DEFAULT_RELAY: &str = "https://dayz-vapour-relay.chrisplayer.workers.dev";

/// One row as published: the server, and the verdict that follows it.
#[derive(serde::Serialize)]
struct Published {
    server: GameServer,
    verdict: Verdict,
    reasons: Vec<String>,
    /// What the A2S pass last saw: `true` answered, `false` did not, `null` never checked.
    ///
    /// An unreachable server is not deleted — it is marked, so the client can keep it out of the way
    /// and still offer it, which is how the launcher this is modelled on treats them too.
    online: Option<bool>,
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

/// One hidden row, written to a diagnostic file.
///
/// The artifact carries only what is published, so the rows the filter removed — and the profile that
/// condemned them — are invisible exactly when they matter most. This is the audit trail: which rows
/// went, why, and what the host looked like at the time.
#[derive(serde::Serialize)]
struct HiddenRow<'a> {
    addr: &'a str,
    name: &'a str,
    map: &'a str,
    players: u16,
    max_players: u16,
    kind: &'static str,
    reason: String,
    ip: &'a str,
    listings_on_ip: usize,
    names_on_ip: usize,
    borrowed_names: usize,
}

/// The published list, as read back for the A2S pass.
#[derive(serde::Deserialize)]
struct PublishedList {
    #[serde(default)]
    servers: Vec<PublishedRow>,
}

#[derive(serde::Deserialize)]
struct PublishedRow {
    server: GameServer,
}

/// Reads what the A2S pass last published, stamped with the relay's idea of when.
///
/// Every failure returns `None`, which means "no verdicts": the one safe outcome, because a verdict
/// that cannot be read must never delete a server.
async fn load_verdicts(relay: &str) -> Option<a2s::Verdicts> {
    let url = format!("{}/artifact/a2s", relay.trim_end_matches('/'));
    let response = reqwest::get(&url).await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let at = response
        .headers()
        .get("x-vapour-generated-at")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    let bytes = response.bytes().await.ok()?;
    let json = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut text = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..]).read_to_end(&mut text).ok()?;
        text
    } else {
        bytes.to_vec()
    };

    let readings: Vec<a2s::Reading> = serde_json::from_slice(&json).ok()?;
    Some(a2s::Verdicts::from_readings(&readings, at))
}

/// Query every server in the published list, and report what answers.
///
/// This is the farm signal as much as the mod signal. A server that answers as itself cannot hide what
/// it runs, and a cluster sharing a mod list, a slot count and a name prefix is visible here and
/// nowhere in Valve's list.
async fn run_a2s(args: &[String], publish: bool) -> Result<(), String> {
    fn value<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1))
    }
    fn number(args: &[String], name: &str, fallback: usize) -> usize {
        value(args, name).and_then(|v| v.parse().ok()).unwrap_or(fallback)
    }

    let concurrency = number(args, "--concurrency", 128).max(1);
    let limit = number(args, "--limit", usize::MAX);
    let skip = number(args, "--skip", 0);
    let out = value(args, "--out").cloned();
    let from = value(args, "--from").cloned();

    // The list comes from a local artifact when given one, otherwise from the relay.
    let raw = match from {
        Some(path) => std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?,
        None => {
            let base = std::env::var("VAPOUR_RELAY").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
            let url = format!("{}/artifact/servers", base.trim_end_matches('/'));
            let response = reqwest::get(&url).await.map_err(|e| format!("{url}: {e}"))?;
            if !response.status().is_success() {
                return Err(format!("{url}: HTTP {}", response.status()));
            }
            response
                .bytes()
                .await
                .map_err(|e| format!("{url}: {e}"))?
                .to_vec()
        }
    };

    let json = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut text = Vec::new();
        flate2::read::GzDecoder::new(&raw[..])
            .read_to_end(&mut text)
            .map_err(|e| format!("the list is not readable gzip: {e}"))?;
        text
    } else {
        raw
    };

    let published: PublishedList =
        serde_json::from_slice(&json).map_err(|e| format!("the list is not the shape we expect: {e}"))?;
    let addrs: Vec<String> = published
        .servers
        .iter()
        .skip(skip)
        .take(limit)
        .map(|row| row.server.addr.clone())
        .collect();

    println!("probing    : {} servers from offset {skip}, {concurrency} at a time", addrs.len());
    let client = a2s::Client::new(std::time::Duration::from_secs(3));
    let client = &client;
    let started = std::time::Instant::now();

    // Owns each address and borrows the client: a reference is copyable, so the futures stay 'static
    // enough for the stream without cloning a socket per task.
    let readings: Vec<a2s::Reading> = futures::stream::iter(
        addrs.into_iter().map(|addr| async move { client.read(&addr).await }),
    )
    .buffer_unordered(concurrency)
    .collect()
    .await;

    println!("elapsed    : {:.1} s", started.elapsed().as_secs_f32());

    let answered = readings.iter().filter(|r| r.answered).count();
    let bots = readings
        .iter()
        .filter(|r| r.info.as_ref().is_some_and(|i| i.bots > 0))
        .count();
    let impossible = readings
        .iter()
        .filter(|r| r.info.as_ref().is_some_and(|i| i.max_players > 127))
        .count();
    let busy = readings
        .iter()
        .filter(|r| r.info.as_ref().is_some_and(|i| i.players > 0))
        .count();
    let with_mods = readings.iter().filter(|r| r.mods.as_ref().is_some_and(|m| !m.mods.is_empty())).count();
    let partial = readings.iter().filter(|r| r.mods.as_ref().is_some_and(|m| !m.complete)).count();

    println!("answered   : {answered} of {}", readings.len());
    println!(
        "plausible  : {}   (answered, no bots, slots the engine can honour)",
        readings.iter().filter(|r| r.is_plausible()).count()
    );
    println!("bots > 0   : {bots}   (fabricated — DayZ has none)");
    println!("slots >127 : {impossible}   (impossible)");
    println!("players > 0: {busy}");
    println!("with mods  : {with_mods}   ({partial} flagged their list incomplete)");

    // The mods everyone shares: the signal that a cluster is one server wearing many ports.
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for reading in &readings {
        if let Some(mods) = &reading.mods {
            for entry in &mods.mods {
                *counts.entry(entry.name.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut top: Vec<(&String, &usize)> = counts.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1));
    println!(
        "top mods   : {}",
        top.iter()
            .take(6)
            .map(|(name, count)| format!("{name} ({count})"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let json = serde_json::to_vec(&readings).map_err(|e| e.to_string())?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&json).map_err(|e| e.to_string())?;
    let bytes = encoder.finish().map_err(|e| e.to_string())?;
    println!(
        "readings   : {:.1} KB raw, {:.1} KB gzipped",
        json.len() as f32 / 1024.0,
        bytes.len() as f32 / 1024.0
    );

    if let Some(path) = out {
        std::fs::write(&path, &bytes).map_err(|e| format!("{path}: {e}"))?;
        println!("wrote      : {path}");
    }

    if publish {
        publish_artifact("a2s", &bytes).await;
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct SweepStats {
    requests: usize,
    failed: usize,
    unresolved: usize,
    /// Empty answers on the first attempt, and buckets still empty after retrying.
    empty_first: usize,
    empty_stubborn: usize,
    /// Queries Valve throttled into a failure, and queries that only succeeded on a retry or in the
    /// patient second pass. A sweep with any `failed` left is a lower bound, and says so.
    throttled: usize,
    recovered: usize,
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

    // The A2S pass: queries the published list and reports what answers. No Valve involvement, so it
    // runs on its own clock later; here it is a mode so the data can be gathered and looked at now.
    if args.iter().any(|a| a == "--a2s") {
        match run_a2s(&args, publish).await {
            Ok(()) => return,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
    }

    // Optional diagnostic: write every hidden row, with the profile that condemned it, as JSON lines.
    let dump_hidden = args
        .iter()
        .position(|a| a == "--dump-hidden")
        .and_then(|i| args.get(i + 1))
        .cloned();

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
        publish_artifact("servers", &bytes).await;
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

    // What the servers said about themselves the last time they were asked. Absent, ancient or
    // unreadable all mean the same thing: no verdicts, and therefore no deletions on their account.
    let relay = std::env::var("VAPOUR_RELAY").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let verdicts = load_verdicts(&relay).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match verdicts.as_ref() {
        Some(v) if v.fresh(now) => println!("verdicts   : {} addresses from the A2S pass", v.len()),
        Some(_) => println!("verdicts   : stale, so ignored"),
        None => println!("verdicts   : none yet (the A2S pass has not run)"),
    }

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
    let mut hidden_rows: Vec<HiddenRow> = Vec::new();
    // One entry per machine and name: the flood collapses here instead of being judged.
    let mut seen_identities: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut collapsed = 0usize;

    for server in &found.servers {
        let assessment = index.assess(server);
        let ip = steam::ip_of(&server.addr);
        outcome.entry(ip).or_insert((assessment.kind, assessment.hide));

        // What the server itself said, when the reading is recent enough to act on. This is the one
        // signal Valve's list cannot give: a master row's `bots` field just mirrors its players, while
        // a server that answers a query with bots is telling on itself. DayZ has no bots.
        let verdict = verdicts
            .as_ref()
            .filter(|v| v.fresh(now))
            .and_then(|v| v.get(&server.addr));
        let online = verdict.map(|(_, answered, _)| answered);

        if let Some((bots, _, _)) = verdict
            && bots > 0
        {
            hidden += 1;
            *by_kind.entry(ReasonKind::Bots).or_insert(0) += 1;
            if !flood.contains(ip) {
                *ordinary.entry(ReasonKind::Bots).or_insert(0) += 1;
            }
            continue;
        }

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
            if dump_hidden.is_some() {
                let profile = index.profile_of(&server.addr);
                hidden_rows.push(HiddenRow {
                    addr: &server.addr,
                    name: &server.name,
                    map: &server.map,
                    players: server.players,
                    max_players: server.max_players,
                    kind: assessment.kind.label(),
                    reason: assessment.reasons.first().cloned().unwrap_or_default(),
                    ip,
                    listings_on_ip: profile.map(|p| p.listings).unwrap_or(0),
                    names_on_ip: profile.map(|p| p.distinct_names).unwrap_or(0),
                    borrowed_names: profile.map(|p| p.borrowed_names).unwrap_or(0),
                });
            }
            continue;
        }

        // Collapse bulk duplication: one entry per machine and name. A farm announcing fifty names on
        // two thousand ports becomes fifty entries, while a community running fifty differently-named
        // servers on one box is untouched. No name is erased — which is why this is a collapse rather
        // than one more reason to hide.
        if !seen_identities.insert(cluster::dedup_key(server)) {
            collapsed += 1;
            continue;
        }

        servers.push(Published {
            server: server.clone(),
            verdict: assessment.verdict,
            reasons: assessment.reasons,
            online,
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
    println!("collapsed  : {collapsed} duplicate announcements (same machine, same name)");
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

    if let Some(path) = dump_hidden.as_deref() {
        let mut body = String::with_capacity(hidden_rows.len() * 200);
        for row in &hidden_rows {
            match serde_json::to_string(row) {
                Ok(line) => {
                    body.push_str(&line);
                    body.push('\n');
                }
                Err(error) => eprintln!("could not serialise a hidden row: {error}"),
            }
        }
        match std::fs::write(path, body) {
            Ok(()) => println!("dumped     : {path}  ({} hidden rows)", hidden_rows.len()),
            Err(error) => eprintln!("could not write {path}: {error}"),
        }
    }

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
                throttled: found.throttled,
                recovered: found.recovered,
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
            publish_artifact("servers", &bytes).await;
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
async fn publish_artifact(name: &str, bytes: &[u8]) {
    let base = std::env::var("VAPOUR_RELAY")
        .unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let token = match std::env::var("VAPOUR_TOKEN") {
        Ok(token) if !token.trim().is_empty() => token,
        _ => {
            eprintln!("--publish needs VAPOUR_TOKEN in the environment");
            std::process::exit(2);
        }
    };
    let url = format!("{}/artifact/{name}", base.trim_end_matches('/'));

    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("could not build an upload client: {error}");
            std::process::exit(2);
        }
    };

    // Tells the relay when this was produced, so a client can decide whether it needs the payload at
    // all with a HEAD instead of downloading it.
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match client
        .put(&url)
        .header("x-vapour-token", token.trim())
        .header("x-vapour-generated-at", generated_at.to_string())
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
        "pages      : {} throttled, {} recovered on retry, {} empty, {} empty after retries",
        found.throttled, found.recovered, found.empty_first, found.empty_stubborn
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

