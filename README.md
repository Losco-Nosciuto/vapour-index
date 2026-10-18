# vapour-index

Builds one file that lists the DayZ servers a launcher can actually offer, and publishes it to a relay.

Valve's master list is not a server list. It is dominated by hosts republishing other people's names on
hundreds of ports — measured on a real sweep, a few hundred addresses account for the great majority of
all announcements. This producer walks the whole list, separates repetition from actual servers, and
publishes a compact index. What it will not do is decide that a server is uninteresting: empty servers,
small communities and oddly named boxes are all legitimate, and only arithmetic impossibility, hosts
republishing other people's names, and addresses publishing an implausible number of listings are kept
out. Everything ambiguous is published, badged, and left to the client.

## How it runs

An hourly GitHub Actions job. Nothing here holds a Valve API key: reads go through a relay that does,
and the filter's cut-offs arrive as repository secrets rather than constants, so publishing this source
does not publish the thresholds.

## Running it locally

```sh
VAPOUR_MAX_SLOTS=... VAPOUR_MEGA_HOST_LISTINGS=... VAPOUR_BORROWED_MIN=... VAPOUR_BORROWED_SHARE=... \
  cargo run -- --out artifact.json.gz
```

The four thresholds are required; there are deliberately no defaults, because a default is a number in
the source.

Set `STEAM_API_KEY` to talk to Valve directly (fast, parallel). Without it the sweep goes through the
relay, which paces requests to its own rate limit and therefore takes much longer.

## What it is not

It does not read anyone's launcher, does not consume a curated list, and does not depend on any
third-party ranking. Valve's master list in, one gzipped artifact out.
