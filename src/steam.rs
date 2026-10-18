//! Talking to Valve's master list, for the producer.
//!
//! Two transports, because the same crate runs in two places:
//!
//! - **direct** — with a Steam Web API key, straight to Valve. Parallel, ~2 minutes for a full sweep.
//!   This is what GitHub Actions does.
//! - **relay** — through our Cloudflare relay, which holds the key. Sequential and paced, because the
//!   relay enforces 120 requests a minute. This is what a local run uses, so the key never has to
//!   exist on a developer machine.
//!
//! ## Why the enumeration is not just 63 queries
//!
//! Valve returns at most **10,000 rows per query** and DayZ has hundreds of thousands of listings.
//! Measured 18/10/2026: `[*` returns exactly 10,000 while its second-level children hold **117,442**.
//! So any bucket that comes back at the cap is *incomplete*, and must be split further.
//!
//! Splitting by name alone branches too fast (63 children per level, ~24,000 requests for the whole
//! list). Splitting by **map** is the second dimension that pays: `[s*` is 6,166 listings, while
//! `[s*` on Chernarus alone is 960. So: one pass at one character, harvest the map values it reveals,
//! then re-query only the capped buckets once per map.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One row from `IGameServersService/GetServerList`, trimmed to what the launcher uses.
///
/// Kept field-for-field compatible with the app's own `GameServer`, because the published artifact is
/// deserialised straight back into that type on the client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GameServer {
    /// `ip:queryport`
    pub addr: String,
    #[serde(rename = "gameport")]
    pub game_port: u16,
    #[serde(rename = "steamid")]
    pub steam_id: String,
    pub name: String,
    pub map: String,
    pub version: String,
    /// As reported to Steam — unreliable for DayZ, `0` for ~98% of servers.
    pub players: u16,
    pub max_players: u16,
    pub bots: u16,
    pub os: String,
    pub secure: bool,
    /// The keyword list: `battleye`, `no3rd`, `lqs…`, the in-game clock, `etm`/`entm`.
    #[serde(rename = "gametype")]
    pub keywords: String,
    #[serde(rename = "gamedir")]
    pub game_dir: String,
}

/// Valve's per-query ceiling.
pub const MASTER_ROW_CAP: usize = 10_000;

/// The name prefixes that together cover the population.
///
/// `name_match` is case-insensitive (`q*` and `Q*` return identical sets), so 26 letters, not 52.
/// Digits and symbols are not optional: DayZ names are overwhelmingly `[TAG] Name`.
pub const NAME_BUCKETS: &[&str] = &[
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
    "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "[", "|",
    "-", "_", "=", "+", ".", "!", "#", "<", "(", "{", "~", "\"", "'", ",", "/", "$", "%", "&", ":",
    ";", "?", "@", "^", ">", " ",
];

/// Valve's master server answers with no `servers` key at all rather than an error when it is asked
/// for too much at once, so a missing answer is worth retrying before it is believed.
const EMPTY_ATTEMPTS: usize = 4;
const EMPTY_BACKOFF_MS: u64 = 400;

/// Rounds of patient, one-at-a-time recovery for buckets Valve throttled, and the pause per round.
const STRAGGLER_ROUNDS: usize = 3;
const STRAGGLER_PAUSE_MS: u64 = 400;

/// The producer's token, when it has one.
///
/// It signs reads to the relay so the relay can tell our own sweep from a stranger's requests, and it
/// is part of the cache key busting that makes a retry different from the attempt it is retrying.
fn producer_token() -> Option<String> {
    std::env::var("VAPOUR_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

/// How deep a name prefix may be subdivided before a saturated bucket is reported rather than split.
const MAX_NAME_DEPTH: usize = 6;

#[derive(Debug)]
pub enum Transport {
    /// Straight to Valve with a key. Fast, parallel.
    Direct(String),
    /// Through the relay, which holds the key. Paced.
    Relay(String),
}

impl Transport {
    fn url(&self, filter: &str, limit: u32) -> String {
        let encoded = url_encode(filter);
        match self {
            Transport::Direct(key) => format!(
                "https://api.steampowered.com/IGameServersService/GetServerList/v1/?filter={encoded}&limit={limit}&format=json&key={key}"
            ),
            Transport::Relay(base) => format!(
                "{}/servers?filter={encoded}&limit={limit}",
                base.trim().trim_end_matches('/')
            ),
        }
    }

    /// Delay between request *starts*.
    ///
    /// The relay rate-limits a stranger to 120 a minute and counts cache hits, so pacing is mandatory
    /// there. Our own sweep signs its reads with the producer token and is allowed far more, so it has
    /// no reason to pace itself into a twenty-minute sweep.
    fn pace(&self) -> Duration {
        match self {
            Transport::Direct(_) => Duration::ZERO,
            Transport::Relay(_) => match producer_token() {
                Some(_) => Duration::ZERO,
                None => Duration::from_millis(550),
            },
        }
    }

    fn concurrency(&self) -> usize {
        match self {
            // Measured 18-19/10/2026 against Valve.
            //
            // Sixteen *identical* queries at once (one bucket): 6/16 came back throttled. Sixteen
            // *distinct* buckets at once: 81k rows in one 3.4 s wall-clock, ~6/16 throttled. So the
            // throttling is about pressure, not about duplicate filters, and a real page costs ~3.3 s
            // no matter how many rows it holds.
            //
            // Eight keeps most of that speed with few enough stragglers for the second pass to clean
            // up, and a sweep only costs as many pages as the distribution demands.
            Transport::Direct(_) => 8,
            Transport::Relay(_) => 8,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Transport::Direct(_) => "valve directly (key from environment)",
            Transport::Relay(_) => "relay (key stays in the relay)",
        }
    }
}

/// Percent-encode a query value. Hand-rolled so the producer has no URL-encoding dependency; the only
/// input is a master filter full of backslashes.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct Envelope {
    response: Option<Body>,
}

#[derive(Debug, Deserialize)]
struct Body {
    servers: Option<Vec<GameServer>>,
}

#[derive(Debug, Default)]
pub struct Enumerated {
    pub servers: Vec<GameServer>,
    pub requests: usize,
    pub failed: usize,
    /// Buckets still at the cap when the sweep stopped: the sweep is a lower bound, and says so.
    pub unresolved: usize,
    /// Queries whose first attempt came back empty, and queries that never filled after retrying.
    pub empty_first: usize,
    pub empty_stubborn: usize,
    /// Queries Valve throttled into a failure, and queries that only succeeded on a retry.
    pub throttled: usize,
    pub recovered: usize,
    /// Map values harvested from the first pass.
    pub maps: Vec<String>,
    /// Addresses already collected, so deduplication stays O(1) instead of rescanning every row.
    seen: std::collections::HashSet<String>,
}

impl Enumerated {
    pub fn complete(&self) -> bool {
        self.failed == 0 && self.unresolved == 0
    }
}

pub struct Sweep<'a> {
    pub transport: &'a Transport,
    pub limit: u32,
    pub max_requests: usize,
    client: reqwest::Client,
    /// Queries whose first attempt came back empty, and queries that never filled after retrying.
    empty_first: std::sync::atomic::AtomicUsize,
    empty_stubborn: std::sync::atomic::AtomicUsize,
    /// Queries Valve throttled, and queries that only succeeded on a retry.
    throttled: std::sync::atomic::AtomicUsize,
    recovered: std::sync::atomic::AtomicUsize,
}

/// One attempt at one query.
#[derive(Debug)]
enum Attempt {
    /// A real answer. It may hold zero servers, and that is a fact about the master list.
    Rows(Vec<GameServer>),
    /// HTTP 200 with **no `servers` key at all**.
    ///
    /// Not an answer. Valve does this when it is asked for too much at once, and it is recognisable by
    /// its speed: ~400 ms, against ~3 s for a real page. Reading it as "empty" is how a sweep reports
    /// itself complete while having read nothing — an empty bucket never trips the row cap, so it is
    /// never subdivided, and the loss is silent.
    Throttled,
}

impl<'a> Sweep<'a> {
    pub fn new(transport: &'a Transport) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("VapourCrawler/0.1")
            .build()
            .map_err(|e| format!("could not build an HTTP client: {e}"))?;
        Ok(Self {
            transport,
            limit: MASTER_ROW_CAP as u32,
            // A ceiling, not a budget: a full sweep needs every bucket the distribution produces, and
            // the real limit is when none is still capped. Valve allows ~100k calls a day.
            max_requests: 12_000,
            client,
            empty_first: std::sync::atomic::AtomicUsize::new(0),
            empty_stubborn: std::sync::atomic::AtomicUsize::new(0),
            throttled: std::sync::atomic::AtomicUsize::new(0),
            recovered: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn stats(&self) -> (usize, usize, usize, usize) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.empty_first.load(Relaxed),
            self.empty_stubborn.load(Relaxed),
            self.throttled.load(Relaxed),
            self.recovered.load(Relaxed),
        )
    }

    /// One request. `limit` is explicit so a retry can differ from the attempt that failed — a retry
    /// that sends the identical request can be answered from a cache, which is how a "retry" ends up
    /// reading the same nothing twice.
    async fn fetch_once(&self, filter: &str, limit: u32) -> Result<Attempt, String> {
        let url = self.transport.url(filter, limit);
        // Never log the URL in direct mode: it carries the key.
        let shown = if url.contains("key=") { "<direct, key redacted>" } else { url.as_str() };

        let mut request = self.client.get(&url);
        // Only the relay needs to recognise us: the token lets it give our own sweep a rate limit a
        // complete sweep can live with. It is never sent to Valve.
        if let (Transport::Relay(_), Some(token)) = (self.transport, producer_token()) {
            request = request.header("x-vapour-token", token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("{shown}: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(160).collect();
            return Err(format!("{shown}: HTTP {status}: {snippet}"));
        }

        // Parsed as a value first: the difference between *no* `servers` key and an *empty* one is the
        // whole point, and a typed `Option<Vec<_>>` erases it.
        let body: serde_json::Value = response.json().await.map_err(|e| format!("{shown}: {e}"))?;
        match body.get("response").and_then(|r| r.get("servers")) {
            Some(serde_json::Value::Array(_)) => {
                let envelope: Envelope = serde_json::from_value(body)
                    .map_err(|e| format!("{shown}: unexpected shape: {e}"))?;
                Ok(Attempt::Rows(
                    envelope.response.and_then(|b| b.servers).unwrap_or_default(),
                ))
            }
            _ => Ok(Attempt::Throttled),
        }
    }

    /// One filter, retried properly if Valve throttled it.
    ///
    /// Every attempt varies the row limit, which is part of the relay's cache key — otherwise a retry
    /// is answered from the cache entry written by the attempt that just failed.
    async fn fetch(&self, filter: &str) -> Result<Vec<GameServer>, String> {
        for attempt in 0..EMPTY_ATTEMPTS {
            let limit = self.limit.saturating_sub(attempt as u32);
            match self.fetch_once(filter, limit).await? {
                Attempt::Rows(rows) => {
                    if attempt > 0 {
                        self.recovered
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if rows.is_empty() {
                        self.empty_first
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if attempt + 1 == EMPTY_ATTEMPTS {
                            self.empty_stubborn
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    return Ok(rows);
                }
                Attempt::Throttled => {
                    if attempt + 1 == EMPTY_ATTEMPTS {
                        self.throttled
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Reported as a failure, never as an empty list: a bucket we could not read
                        // must not look like a bucket that holds nothing.
                        return Err(format!("{filter}: throttled on every attempt"));
                    }
                    let backoff = EMPTY_BACKOFF_MS * (1 << attempt);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
        unreachable!("the loop returns on the last attempt")
    }

    /// Fetch a batch of filters, honouring pacing and bounded concurrency.
    ///
    /// `join_all` rather than a spawn loop: it polls every future on this task, so the semaphore
    /// genuinely bounds how many requests are in flight. Collecting futures into a `Vec` and awaiting
    /// them one by one would look parallel and be strictly sequential — an easy mistake with an ugly
    /// symptom, namely a sweep that takes hours with no explanation.
    async fn fetch_batch(&self, filters: Vec<String>) -> Vec<(String, Option<Vec<GameServer>>)> {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(
            self.transport.concurrency().max(1),
        ));
        let pace = self.transport.pace();
        let started = std::time::Instant::now();
        let issued = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let work = filters.into_iter().map(|filter| {
            let gate = std::sync::Arc::clone(&gate);
            let issued = std::sync::Arc::clone(&issued);
            async move {
                let _permit = gate.acquire().await.ok();
                if !pace.is_zero() {
                    let index = issued.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let due = started + pace * index as u32;
                    let now = std::time::Instant::now();
                    if due > now {
                        tokio::time::sleep(due - now).await;
                    }
                }
                let rows = self.fetch(&filter).await.ok();
                (filter, rows)
            }
        });

        futures::future::join_all(work).await
    }

    /// The whole sweep: a ladder of name prefixes, deepening only where a bucket came back full.
    ///
    /// The first version split a saturated bucket across every map value instead — one query per
    /// `prefix x map`. It looked thorough and was the opposite: a farm publishing two thousand
    /// listings spreads them over every map, so the split does not bring it back under the cap, while
    /// every genuinely small bucket gets chopped into a hundred tiny pages that each cost a full
    /// master scan. Names are what we are partitioning by, and a second character divides a bucket
    /// far more evenly — so the ladder lengthens the prefix instead, and only for full buckets.
    pub async fn run(&self) -> Result<Enumerated, String> {
        let mut result = Enumerated::default();

        let mut level: Vec<String> = NAME_BUCKETS.iter().map(|p| (*p).to_string()).collect();
        let mut depth = 1;
        let mut stragglers: Vec<String> = Vec::new();

        while !level.is_empty() {
            let filters: Vec<String> = level
                .iter()
                .map(|p| format!("\\appid\\221100\\name_match\\{p}*"))
                .collect();
            let batches = self.fetch_batch(filters).await;

            let mut deeper: Vec<String> = Vec::new();
            for (filter, rows) in batches {
                result.requests += 1;
                let prefix = filter
                    .rsplit('\\')
                    .next()
                    .unwrap_or_default()
                    .trim_end_matches('*')
                    .to_string();

                match rows {
                    None => {
                        result.failed += 1;
                        stragglers.push(filter);
                    }
                    Some(rows) => {
                        if rows.len() >= MASTER_ROW_CAP {
                            if depth < MAX_NAME_DEPTH {
                                // Every character the first one can be: a name may start with `[`,
                                // and its second character may be a bracket too.
                                for next in NAME_BUCKETS {
                                    deeper.push(format!("{prefix}{next}"));
                                }
                            } else {
                                result.unresolved += 1;
                            }
                        }
                        collect(&mut result, rows);
                    }
                }
            }

            // Stop cleanly rather than overrun. The next level is the only thing that costs anything,
            // so it is budgeted before it is issued, and whatever is left over is reported.
            if result.requests + deeper.len() > self.max_requests {
                result.unresolved += deeper.len();
                break;
            }

            level = deeper;
            depth += 1;
        }

        // Recovery rounds over whatever failed: throttling is caused by asking for too much at once,
        // so the retry that works is the patient one. One query at a time, a pause growing with each
        // round, and a bounded number of rounds. Anything still unread at the end stays counted as a
        // failure, which is what makes the sweep report itself a lower bound instead of a complete
        // list — the difference between a number and a lie.
        for round in 0..STRAGGLER_ROUNDS {
            if stragglers.is_empty() {
                break;
            }
            let mut still_failing = Vec::new();
            for filter in stragglers.drain(..) {
                let pause = STRAGGLER_PAUSE_MS * (round as u64 + 1);
                tokio::time::sleep(Duration::from_millis(pause)).await;

                match self.fetch_once(&filter, self.limit - 1 - round as u32).await {
                    Ok(Attempt::Rows(rows)) => {
                        result.failed = result.failed.saturating_sub(1);
                        self.recovered
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if rows.len() >= MASTER_ROW_CAP {
                            // Recovered, but still full: honest about what was not resolved.
                            result.unresolved += 1;
                        }
                        collect(&mut result, rows);
                    }
                    _ => still_failing.push(filter),
                }
            }
            stragglers = still_failing;
        }
        result.failed = stragglers.len();

        // The map values the sweep revealed, for the report and the artifact.
        let mut maps: Vec<String> = result
            .servers
            .iter()
            .map(|s| s.map.trim().to_string())
            .filter(|m| !m.is_empty())
            .collect();
        maps.sort();
        maps.dedup();
        result.maps = maps;

        let (empty_first, empty_stubborn, throttled, recovered) = self.stats();
        result.empty_first = empty_first;
        result.empty_stubborn = empty_stubborn;
        result.throttled = throttled;
        result.recovered = recovered;

        Ok(result)
    }
}

/// Append, dropping addresses already seen.
fn collect(result: &mut Enumerated, rows: Vec<GameServer>) {
    for row in rows {
        if result.seen.insert(row.addr.clone()) {
            result.servers.push(row);
        }
    }
}

pub fn ip_of(addr: &str) -> &str {
    addr.split(':').next().unwrap_or(addr)
}
