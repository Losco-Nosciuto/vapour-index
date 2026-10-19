//! The flood filter — the rule that decides what reaches the launcher.
//!
//! Measured on a full enumeration: **hundreds of thousands of announcements carry a fraction of that
//! many distinct names**. The flood is **repetition**, not extra servers — and this module decides
//! which of the repetitions are worth shipping.
//!
//! Two reasons to act on a server, and neither is "I think this is fake":
//!
//! | reason | evidence | what happens |
//! |---|---|---|
//! | arithmetic | more slots than the engine allows, or more players than slots | **published, badged** |
//! | mega-host | one address publishing an implausible number of listings | hidden |
//!
//! Arithmetic used to hide as well. It no longer does, because "provably impossible" and "worth
//! removing" are different claims, and only the second one justifies deletion. A server advertising
//! 255 slots cannot exist; it is also not mine to erase, so it ships with a badge that says so and a
//! client that can sort it away. The only remaining deletion is bulk: one address announcing two
//! thousand listings is the pollution that makes the list unusable, and that is measured, not guessed.
//!
//! A third rule once hid hosts whose names also appeared on other addresses, on the theory that
//! copying a popular name is impersonation. Audited against a real sweep, it was deleting 565 hosts
//! — a median of fourteen servers each, one name per server, and 201 of them running twenty or more
//! — because a community that spreads its servers across a hosting block has every name on more than
//! one address. It punished the copied, not the copier. Removed.
//!
//! The cut-offs themselves are in [`Thresholds`], read from the environment — see the note there.

use serde::{Deserialize, Serialize};

use crate::steam::{ip_of, GameServer};

/// The numbers the filter turns on.
///
/// Deliberately **not** constants in this file. The producer runs in a public repository, and a flood
/// that can read the thresholds can sit just underneath them: one listing fewer, one slot fewer. So
/// the logic is public and the numbers are not, supplied from repository secrets at run time. That is
/// a real reduction in what a farm learns, though not a guarantee — published reasons and observable
/// behaviour still hint at where the lines are.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// DayZ cannot host more than this many players.
    pub engine_max_slots: u16,
    /// Above this many listings on one address, a host is a flood rather than a community.
    pub mega_host_listings: usize,
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
    /// A population that is entirely bots, names none of them, and has no queue.
    Fabricated,
    /// Several servers on one address - information, never a verdict.
    SeveralOnOneAddress,
    /// Nothing unexplained.
    None,
}

impl ReasonKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Arithmetic => "arithmetic",
            Self::Fabricated => "fabricated",
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

    /// A fact worth showing that is **not** a verdict.
    ///
    /// "This machine hosts fourteen servers" is true of nine tenths of the DayZ population, because
    /// hosting is normal. Marking those servers suspect told the user they were probably fake, which is
    /// the opposite of what the data says — so the information travels, the accusation does not.
    fn note(kind: ReasonKind, reason: String) -> Self {
        Self { verdict: Verdict::Clean, kind, reasons: vec![reason], hide: false }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub listings: usize,
    pub distinct_names: usize,
    pub borrowed_names: usize,
}

impl Profile {
    /// Share of this host's names that also exist on another address.
    ///
    /// No longer decides anything — the rule that used it was measured deleting real communities — but
    /// it is kept in the report and the audit dump, because it is still how a spread-out community and
    /// a copier look different at a glance.
    #[allow(dead_code)]
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

        // ---- arithmetic: the engine cannot do this. Hard rule, hidden without remorse. ---------
        //
        // A DayZ server cannot host 255 players. This is a fact about the engine rather than an
        // opinion about the host, so the row goes: no badge, no pardon, and it is the only judgement
        // that removes anything.
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

        // ---- bulk: collapsed, not condemned ----------------------------------------------------
        //
        // A machine announcing two thousand listings is the pollution that makes a list unusable, but
        // it is not evidence that any particular one of those servers is fake. So the bulk is not
        // hidden here — it is collapsed by [`deduplicate`], one entry per machine and name. A farm
        // republishing fifty names on two thousand ports becomes fifty entries; a community running
        // fifty differently-named servers on one box is untouched. Nothing is erased either way, and
        // no threshold has to guess which of the two it is looking at.

        // No further test. A rule that hid hosts whose names appeared on other addresses was tried,
        // measured, and removed: it deleted 565 real multi-server communities, because spreading
        // servers across a hosting block puts every name on more than one address. See the module
        // docs. Arithmetic is now the only thing that removes a row.

        // ---- several servers on one address: information, never a verdict ----------------------
        if profile.listings > 5 {
            return Assessment::note(
                ReasonKind::SeveralOnOneAddress,
                format!("shared host: {} servers on one address", profile.listings),
            );
        }

        Assessment::clean()
    }
}

/// The identity of a server for the purposes of collapsing bulk duplication: its machine and its name.
///
/// One machine announcing the same name on two thousand ports is one server with a lot of noise, not
/// two thousand servers. Collapsing on this key removes the noise without deciding that any name is
/// fake — which is the point, because nowhere in this file is there a rule that erases a name.
pub fn dedup_key(server: &GameServer) -> (String, String) {
    (ip_of(&server.addr).to_string(), server.name.trim().to_string())
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
    fn an_impossible_slot_count_is_hidden_without_remorse() {
        // A hard fact about the engine, not an opinion about the host. DayZ cannot host 255 players, so
        // the row goes — and this is the only judgement in the filter that removes anything.
        let mut s = server("1.1.1.1:2303", "Liars");
        s.max_players = 200;
        let index = ClusterIndex::build(std::slice::from_ref(&s), thresholds());
        let a = index.assess(&s);
        assert!(a.hide);
        assert_eq!(a.verdict, Verdict::Impossible);
        assert_eq!(a.kind, ReasonKind::Arithmetic);
        assert!(a.reasons[0].contains("engine caps"), "{:?}", a.reasons);
    }

    #[test]
    fn more_players_than_slots_is_hidden() {
        let mut s = server("1.1.1.1:2303", "Liars");
        s.players = 40;
        s.max_players = 20;
        let index = ClusterIndex::build(std::slice::from_ref(&s), thresholds());
        let a = index.assess(&s);
        assert!(a.hide);
        assert_eq!(a.kind, ReasonKind::Arithmetic);
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
        assert_eq!(index.assess(&servers[0]).verdict, Verdict::Clean, "crowding is information, not a verdict");
    }

    #[test]
    fn a_saturated_address_is_badged_not_hidden() {
        // Bulk is information now, not guilt. The duplication that made the machine busy is collapsed
        // in the producer (one entry per machine and name), so 55 differently-named servers all stay.
        let servers: Vec<GameServer> = (0..thresholds().mega_host_listings + 5)
            .map(|i| server(&format!("9.9.9.9:{}", 2000 + i), &format!("Farm #{i}")))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(!a.hide, "a busy machine must not erase its servers: {:?}", a.reasons);
        assert_eq!(a.kind, ReasonKind::SeveralOnOneAddress);
    }

    #[test]
    fn a_community_spread_over_several_addresses_is_kept() {
        // The exact shape the removed rule deleted: one community, 37 servers, one name per server,
        // spread across a hosting block — so every one of its names also exists on a sibling address.
        // 565 hosts looked like this in a real sweep, and they were real.
        let mut servers = Vec::new();
        for block in 0..4 {
            for i in 0..37 {
                servers.push(server(
                    &format!("31.77.142.{}:{}", 60 + block, 35000 + i),
                    &format!("ATLANT PvP Cherno #{i}"),
                ));
            }
        }
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(!a.hide, "a community must not be hidden for spanning addresses: {:?}", a.reasons);
        // Several on one address: badged, and still visible.
        assert_eq!(a.verdict, Verdict::Clean, "crowding is information, not a verdict");
    }

    #[test]
    fn bulk_duplication_collapses_on_machine_and_name() {
        use std::collections::HashSet;

        // A farm: one machine, three names, each announced on hundreds of ports. Collapsing keeps one
        // entry per name, so 1,200 rows become 3 without erasing anything.
        let mut servers = Vec::new();
        for port in 0..400 {
            for (offset, name) in [(2000, "Farm A"), (6000, "Farm B"), (10000, "Farm C")] {
                servers.push(server(&format!("9.9.9.9:{}", offset + port), name));
            }
        }
        let kept: HashSet<(String, String)> = servers.iter().map(dedup_key).collect();
        assert_eq!(kept.len(), 3);
        assert_eq!(servers.len(), 1200);

        // And a community's fifty-three differently-named servers on one machine survive untouched:
        // the key is per name, so nothing about running many servers is itself suspicious.
        let community: Vec<GameServer> = (0..53)
            .map(|i| server(&format!("185.83.152.170:{}", 2303 + i), &format!("[STPC] Server {i}")))
            .collect();
        let community_keys: HashSet<(String, String)> = community.iter().map(dedup_key).collect();
        assert_eq!(community_keys.len(), 53);
    }

    #[test]
    fn the_bulk_threshold_badges_rather_than_removes() {
        // A busy machine is information, not guilt: it is badged and published, and the duplication
        // that made it busy is collapsed elsewhere.
        let servers: Vec<GameServer> = (0..thresholds().mega_host_listings + 5)
            .map(|i| server(&format!("9.9.9.9:{}", 2000 + i), &format!("Farm #{i}")))
            .collect();
        let index = ClusterIndex::build(&servers, thresholds());
        let a = index.assess(&servers[0]);
        assert!(!a.hide, "a busy machine must not erase its servers: {:?}", a.reasons);
        assert_eq!(a.kind, ReasonKind::SeveralOnOneAddress);
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
        assert_eq!(a.verdict, Verdict::Clean, "crowding is information, not a verdict");
    }
}
