//! The flood filter — the rule that decides what reaches the launcher.
//!
//! Measured on a full enumeration: **hundreds of thousands of announcements carry a fraction of that
//! many distinct names**. The flood is **repetition**, not extra servers — and this module decides
//! which of the repetitions are worth shipping.
//!
//! Three reasons to hide a server, and they are deliberately different in kind:
//!
//! | reason | evidence | certainty |
//! |---|---|---|
//! | arithmetic | more slots than the engine allows, or more players than slots | proof |
//! | impersonation | most of a host's names also run on other addresses | strong |
//! | mega-host | a single address publishing an implausible number of listings | strong |
//!
//! Everything else is **kept**, including the ambiguous band between a plausible handful and an
//! implausible flood — because a real community can legitimately run a dozen servers on one box. Hiding
//! real servers is the exact failure this whole exercise set out to fix.
//!
//! Padding that survives this filter is settled by **A2S on the client**: a pad claims a full house
//! while `A2S_PLAYERS` names three.
//!
//! The cut-offs themselves are in [`Thresholds`], read from the environment — see the note there.

use serde::{Deserialize, Serialize};

use crate::steam::{ip_of, GameServer};

/// The numbers the filter turns on.
///
/// Deliberately **not** constants in this file. The producer runs in a public repository, and a flood
/// that can read the thresholds can sit just underneath them: one listing fewer, one slot fewer, one
/// borrowed name fewer. So the logic is public and the numbers are not, supplied from repository
/// secrets at run time. That is a real reduction in what a farm learns, though not a guarantee —
/// published reasons and observable behaviour still hint at where the lines are.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// DayZ cannot host more than this many players.
    pub engine_max_slots: u16,
    /// Above this many listings on one address, a host is a flood rather than a community.
    pub mega_host_listings: usize,
    /// Names also seen on other addresses, beyond which a host is impersonating rather than hosting.
    pub borrowed_name_min: usize,
    pub borrowed_name_share: f32,
}

impl Thresholds {
    /// Read every threshold from the environment.
    ///
    /// No fallbacks on purpose: a default is a number in the source, which is the thing this type
    /// exists to avoid. A missing variable is a configuration error, reported as one.
    pub fn from_env() -> Result<Self, String> {
        fn get(name: &str) -> Result<String, String> {
            std::env::var(name).map_err(|_| {
                format!("{name} is not set — the producer reads its thresholds from the environment")
            })
        }
        fn parse<T: std::str::FromStr>(name: &str) -> Result<T, String> {
            let value = get(name)?;
            value
                .trim()
                .parse::<T>()
                .map_err(|_| format!("{name} is not a valid number: {value:?}"))
        }
        Ok(Self {
            engine_max_slots: parse("VAPOUR_MAX_SLOTS")?,
            mega_host_listings: parse("VAPOUR_MEGA_HOST_LISTINGS")?,
            borrowed_name_min: parse("VAPOUR_BORROWED_MIN")?,
            borrowed_name_share: parse("VAPOUR_BORROWED_SHARE")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing unexplained.
    Clean,
    /// Unexplained but plausible — shown with a badge, never hidden on its own.
    Suspected,
    /// Provably fake.
    Impossible,
}

/// Why a row was hidden or badged. Kept as a value rather than only as prose, so the run can be
/// tallied by cause — a total of "222,945 hidden" says nothing; the split says whether the filter is
/// catching farms or eating communities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    /// More slots than the engine allows, or more players than slots.
    Arithmetic,
    /// One address publishing MEGA_HOST_LISTINGS or more.
    MegaHost,
    /// A host whose names mostly also run on other addresses.
    Impersonation,
    /// Several servers on one address — badged, never hidden.
    SeveralOnOneAddress,
    /// Nothing unexplained.
    None,
}

impl ReasonKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Arithmetic => "arithmetic",
            Self::MegaHost => "mega-host",
            Self::Impersonation => "impersonation",
            Self::SeveralOnOneAddress => "several-on-one-address",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub verdict: Verdict,
    /// The single cause behind the verdict, for tallying.
    pub kind: ReasonKind,
    pub reasons: Vec<String>,
    /// True when the producer should keep this server out of the published list.
    pub hide: bool,
}

impl Assessment {
    fn clean() -> Self {
        Self { verdict: Verdict::Clean, kind: ReasonKind::None, reasons: Vec::new(), hide: false }
    }

    fn hide_with(verdict: Verdict, kind: ReasonKind, reason: String) -> Self {
        Self { verdict, kind, reasons: vec![reason], hide: true }
    }

    fn badge(kind: ReasonKind, reason: String) -> Self {
        Self { verdict: Verdict::Suspected, kind, reasons: vec![reason], hide: false }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub listings: usize,
    pub distinct_names: usize,
    pub borrowed_names: usize,
}

impl Profile {
    pub fn borrowed_share(&self) -> f32 {
        if self.distinct_names == 0 {
            return 0.0;
        }
        self.borrowed_names as f32 / self.distinct_names as f32
    }
}

/// Cross-row context for one whole enumeration.
pub struct ClusterIndex {
    profiles: std::collections::HashMap<String, Profile>,
    thresholds: Thresholds,
}

impl ClusterIndex {
    /// Build over **everything**, after deduplication.
    ///
    /// Clustering a single response shows every host with a handful of listings and concludes nothing.
    /// Farms publish across name buckets, so the index has to see the whole sweep.
    pub fn build(servers: &[GameServer], thresholds: Thresholds) -> Self {
        let mut names_on_ip: std::collections::HashMap<&str, std::collections::HashSet<&str>> =
            std::collections::HashMap::new();
        let mut ips_of_name: std::collections::HashMap<&str, std::collections::HashSet<&str>> =
            std::collections::HashMap::new();
        let mut listings_on_ip: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        for server in servers {
            let ip = ip_of(&server.addr);
            *listings_on_ip.entry(ip).or_insert(0) += 1;
            names_on_ip.entry(ip).or_default().insert(server.name.as_str());
            ips_of_name.entry(server.name.as_str()).or_default().insert(ip);
        }

        let profiles = names_on_ip
            .into_iter()
            .map(|(ip, names)| {
                let borrowed = names
                    .iter()
                    .filter(|name| ips_of_name.get(*name).is_some_and(|ips| ips.len() > 1))
                    .count();
                let profile = Profile {
                    listings: listings_on_ip.get(ip).copied().unwrap_or(0),
                    distinct_names: names.len(),
                    borrowed_names: borrowed,
                };
                (ip.to_string(), profile)
            })
            .collect();

        Self { profiles, thresholds }
    }

    pub fn profile_of(&self, addr: &str) -> Option<&Profile> {
        self.profiles.get(ip_of(addr))
    }

    pub fn ip_count(&self) -> usize {
        self.profiles.len()
    }

    pub fn assess(&self, server: &GameServer) -> Assessment {
        let thresholds = self.thresholds;

        // ---- arithmetic: the engine cannot do this -------------------------------------------
        if server.max_players > thresholds.engine_max_slots {
            return Assessment::hide_with(
                Verdict::Impossible,
                ReasonKind::Arithmetic,
                format!(
                    "advertises {} slots; the engine caps at {}",
                    server.max_players, thresholds.engine_max_slots
                ),
            );
        }
        if server.max_players > 0 && server.players > server.max_players {
            return Assessment::hide_with(
                Verdict::Impossible,
                ReasonKind::Arithmetic,
                format!("claims {} players in {} slots", server.players, server.max_players),
            );
        }

        let Some(profile) = self.profile_of(&server.addr) else {
            return Assessment::clean();
        };

        // ---- a single address publishing an implausible number of listings ---------------------
        if profile.listings >= thresholds.mega_host_listings {
            return Assessment::hide_with(
                Verdict::Suspected,
                ReasonKind::MegaHost,
                format!("host publishes {} listings on one address", profile.listings),
            );
        }

        // ---- a host whose names mostly belong to other hosts ----------------------------------
        let impersonating = profile.borrowed_names >= thresholds.borrowed_name_min
            && profile.borrowed_share() >= thresholds.borrowed_name_share;
        if impersonating {
            return Assessment::hide_with(
                Verdict::Suspected,
                ReasonKind::Impersonation,
                format!(
                    "{} of its {} names also run on other addresses",
                    profile.borrowed_names, profile.distinct_names
                ),
            );
        }

        // ---- several servers on one address: visible, badged, never hidden --------------------
        if profile.listings > 5 {
            return Assessment::badge(
                ReasonKind::SeveralOnOneAddress,
                format!(
                    "host runs {} listings on one address — common for communities, and for pads",
                    profile.listings
                ),
            );
        }

        Assessment::clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Thresholds for tests only — deliberately *not* the production numbers, so that publishing this
    /// source does not publish the real cut-offs. The behaviour is what is under test, not the values.
    fn thresholds() -> Thresholds {
        Thresholds {
            engine_max_slots: 120,
            mega_host_listings: 50,
            borrowed_name_min: 4,
            borrowed_name_share: 0.6,
        }
    }

    fn server(addr: &str, name: &str) -> GameServer {
        GameServer {
            addr: addr.to_string(),
            name: name.to_string(),
            max_players: 60,
            ..Default::default()
        }
    }

    #[test]
    fn a_lone_server_is_kept_and_clean() {
        let servers = vec![server("1.1.1.1:2303", "Quiet PVE")];
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert_eq!(a.verdict, Verdict::Clean);
        assert!(!a.hide);
    }

    #[test]
    fn an_impossible_slot_count_is_hidden_whatever_else_is_true() {
        let mut s = server("1.1.1.1:2303", "Liars");
        s.max_players = 200;
        let index = ClusterIndex::build(std::slice::from_ref(&s), thresholds());
        let a = index.assess(&s);
        assert_eq!(a.verdict, Verdict::Impossible);
        assert!(a.hide);
    }

    #[test]
    fn more_players_than_slots_is_hidden() {
        let mut s = server("1.1.1.1:2303", "Liars");
        s.players = 40;
        s.max_players = 20;
        let index = ClusterIndex::build(std::slice::from_ref(&s), thresholds());
        assert!(index.assess(&s).hide);
    }

    #[test]
    fn a_real_community_on_nine_servers_is_not_hidden() {
        // Nine instances on ONE box: same IP, nine ports. A cut at five listings would have hidden
        // this, and hiding real communities is the failure the whole filter exists to avoid.
        let servers: Vec<GameServer> = (0..9)
            .map(|i| server(&format!("185.83.152.170:{}", 2303 + i), &format!("[STPC] Server {i}")))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        for s in &servers {
            let a = index.assess(s);
            assert!(!a.hide, "{} was hidden: {:?}", s.name, a.reasons);
        }
        // Several on one address, but with its own names: badged, not hidden.
        assert_eq!(index.assess(&servers[0]).verdict, Verdict::Suspected);
    }

    #[test]
    fn a_saturated_address_is_hidden() {
        let servers: Vec<GameServer> = (0..thresholds().mega_host_listings)
            .map(|i| server(&format!("9.9.9.9:{}", 2000 + i), &format!("Farm #{i}")))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(a.hide);
        assert!(a.reasons[0].contains("listings on one address"), "{:?}", a.reasons);
    }

    #[test]
    fn a_host_republishing_other_peoples_names_is_hidden() {
        let mut servers = Vec::new();
        for i in 0..40 {
            for (port, name) in [
                (2303, "POPULAR #1"),
                (2304, "POPULAR #2"),
                (2305, "POPULAR #3"),
                (2306, "POPULAR #4"),
            ] {
                servers.push(server(&format!("10.0.{i}.1:{port}"), name));
            }
        }
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(a.hide, "{:?}", a.reasons);
        assert!(a.reasons[0].contains("also run on other addresses"), "{:?}", a.reasons);
    }

    #[test]
    fn a_shared_default_name_alone_is_not_impersonation() {
        // `nitrado.net gameserver` runs on many genuine IPs that never renamed their box.
        let servers: Vec<GameServer> = (0..177)
            .map(|i| server(&format!("10.1.{}.{}:2303", i / 256, i % 256), "nitrado.net gameserver"))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        assert!(!index.assess(&servers[0]).hide);
    }

    #[test]
    fn an_ambiguous_host_stays_visible() {
        // Between a plausible handful and an implausible flood: badged, never hidden.
        let servers: Vec<GameServer> = (0..30)
            .map(|i| server(&format!("7.7.7.7:{}", 3000 + i), &format!("Community #{i}")))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(!a.hide, "ambiguous hosts must stay visible: {:?}", a.reasons);
        assert_eq!(a.verdict, Verdict::Suspected);
    }
}
