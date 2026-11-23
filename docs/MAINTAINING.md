# CyberDigest: maintainer and technical notes

Full detail for whoever maintains this deployment (or forks it). Visitors only need the [hosted dashboard](https://brettmvincent.github.io/cyberdigest/).

CyberDigest pulls ~100 curated feeds (CERTs, vendor PSIRTs, threat research, a few news outlets) plus CISA KEV, FIRST EPSS, CVE records and public-PoC data. It folds duplicate coverage into single stories and ranks them with transparent rules. Each story shows **why** it ranks where it does. It runs entirely on GitHub: Actions refreshes the data every 15 minutes and Pages serves the dashboard. No servers, no API keys, no LLM.

## What you get

- **Overview (situation room):** this is the landing page. It has:
  - Animated headline numbers, each compared with last week.
  - A **world map** with three layers: countries *in the news*, *actor origin* (MISP galaxy attribution) and *actor targets* (MISP profiles).
  - Stories-by-priority and CISA KEV-per-week charts.
  - Active threat actors with sparklines, most-affected vendors, weakness types (CWE), CVSS and EPSS distributions, and source mix.
  - Click-through: every country, bar and row filters the stories behind it.
- **Threat-actor profiles:** aliases, description, suspected origin and known targets on a map, 30-day activity, the malware, vendors and CVEs mentioned alongside, and recent stories.
- **Ransomware (counts only: no victim names, logos, chats or ransom notes):** it shows:
  - weekly leak-site claims (RansomLook; Ransomware.live with an optional free key), always labelled as unverified claims;
  - group trends and group profiles laid out like CISA #StopRansomware advisories: CVEs exploited and tools used (Will Thomas's Ransomware Vulnerability and Tool Matrices), plus ransom-note, chat and payment counts and pivot links;
  - "KEV newly linked to ransomware" (CISA's silent Unknown→Known flips);
  - a tool-hunting list for this month's most active groups.
- **Richer CVE cards:** each CVE card shows:
  - "Ransomware: Known (CISA) · Qilin, Akira";
  - multi-source exploitation from CIRCL Vulnerability-Lookup (CISA, ENISA, Shadowserver honeypots and others, including CVEs exploited but not yet in CISA KEV);
  - public detection content (Nuclei, Sigma, ET Open, YARA Forge, CIRCL Rulezet);
  - a **detection gap** flag for exploited CVEs with no public rule.
- **Priority queue, not a newspaper.** Stories are banded P1 *Act now* → P4 *Context*. P4 is hidden by default. Each row shows the rules that fired (`KEV +2d`, `SSVC: active`, `EPSS 15% (92nd)`, `New public PoC`, `5 sources in 24h`).
- **Duplicates collapsed.** The same CVE or story across 20 outlets becomes one row with "+19 sources". The authoritative source leads.
- **Signals rail:**
  - new CISA KEV entries, with due dates and the ransomware flag
  - EPSS movers
  - most-covered CVEs this week
  - actor, malware and vendor mention trends against a baseline
  - your watchlist
  - pipeline health
- **CVE table:** sortable by CVSS, EPSS, 24h change, KEV, source count. Filter to KEV, public PoC or EPSS ≥ 8.8%, and export to CSV.
- **Operator ergonomics:**
  - a `Ctrl+K` command palette to jump to any story, CVE, actor, vendor or action
  - hover cards on CVEs and actors
  - toasts when new P1 stories arrive, and undo when you hide a story
  - keyboard navigation (`j/k/o/v/w/m`, `1–4` for views, `/`, `?`)
  - token search (`vendor:fortinet kev:yes since:7d`, `origin:RU`, `country:UA`, `target:DE`, `date:2026-11-20`)
  - filter state kept in the URL, so views can be shared as links
  - "new since last visit" markers
  - watch/mute lists, stored only in your browser

## Priority rules

| Band | Fires when |
|---|---|
| **P1 Act now** | Any of these:<br>• CVE added to CISA KEV in the last 7 days.<br>• KEV entry with ransomware use, due within 14 days.<br>• CISA SSVC *Exploitation: active* on a CVE published in the last 30 days.<br>• A government or vendor advisory (tier A) says it is exploited.<br>A CVE only listed in passing in a round-up caps at P2. |
| **P2 High** | Any of these:<br>• KEV entry from the last year.<br>• Exploitation reported by research or news.<br>• Listed as exploited by a non-CISA catalogue (ENISA, Shadowserver…) but not yet by CISA KEV.<br>• Honeypot exploitation in the last 7 days.<br>• CISA newly linked the CVE to ransomware.<br>• A ransomware group uses a recent KEV or high-EPSS CVE.<br>• EPSS ≥ 0.088 and CVSS ≥ 7, for CVEs from the last year.<br>• EPSS up ≥ 10 points in a day.<br>• Public PoC first seen in the last 72h on a high-severity CVE.<br>• 3+ independent sources within 24h. |
| **P3 Monitor** | Advisories (excluding bulk streams), and research naming a CVE, threat actor or malware family. |
| **P4 Context** | Everything else, including bulk advisory streams (MSRC, Ubuntu/Red Hat/Debian notices, ZDI, CCCS) unless a rule above fires. |

All thresholds live in [`pipeline/src/config.ts`](../pipeline/src/config.ts).

## How it works

```
GitHub Actions (every 15 min, off-peak minutes)
  ├─ restore state from the `data` branch (seen items, ETags, EPSS snapshot, caches)
  ├─ fetch feeds (conditional GET, honest bot User-Agent, 20s timeout)
  ├─ strip all HTML → plain text; extract CVEs, vendors, actors, malware
  ├─ enrich: CISA KEV · FIRST EPSS (daily CSV) · cvelistV5 (CVSS, CISA-ADP SSVC) · PoC-in-GitHub
  ├─ cluster: same CVE in both headlines, overlapping CVE sets, or similar headlines across outlets
  ├─ score with ordered rules → write web/public/data/*.json
  ├─ force-push state as a single orphan commit to `data`
  └─ build the Svelte dashboard → deploy to GitHub Pages
```

- **State** lives on the orphan `data` branch as a single commit, so the repo never grows. Each push also keeps the scheduled workflow from being auto-disabled after 60 days.
- **Freshness:** expect data 15–40 minutes behind real time, because of the cron interval, Actions scheduling delays and the 10-minute Pages CDN cache. The header always shows "Updated N min ago". It turns amber after 45 minutes and red after 90.
- **Entity dictionary:** rebuilt weekly from the MISP galaxy (threat actors, ransomware, Malpedia, MITRE ATT&CK groups and software) plus CISA KEV vendor names and a product→vendor alias map in [`pipeline/src/dicts.ts`](../pipeline/src/dicts.ts).

## Maintainers only: running a copy

> **Visitors don't need anything in this section.** The dashboard above is already hosted and updated automatically.
> These notes are for whoever maintains this deployment, or for anyone who wants to fork it and run their own.

### Setup (one time)

1. Create a **public** repository named `cyberdigest`. GitHub Pages on the Free plan requires a public repo.
2. Push this code to `main`.
3. **Settings → Pages → Build and deployment → Source: GitHub Actions.**
4. **Actions → Update CyberDigest → Run workflow.** The first run builds the dictionary and state (about a minute).
5. Open `https://<your-user>.github.io/cyberdigest/`.

CVE-record and PoC enrichment fills in over the first few hours (200 lookups per run, the most important CVEs first). Trend baselines appear after 14 days of history.

### Optional free API keys

Add these under **Settings → Secrets and variables → Actions**. Each source is skipped cleanly (and shown as "skipped" on the Sources page) when its key is missing.

| Secret | Where to get it | What it adds |
|---|---|---|
| `RANSOMWARE_LIVE_KEY` | Free PRO key at ransomware.live/my | Leak-site claim counts by group, sector and victim country (aggregated; raw data is never published) |
| `NVD_API_KEY` | nvd.nist.gov/developers/request-an-api-key | Faster NVD paging (works without a key, just slower) |
| `CIRCL_API_KEY` | vulnerability.circl.lu account | 40 instead of 20 requests/min to CIRCL Vulnerability-Lookup |

## Ransomware data policy

CyberDigest never publishes victim names, victim logos, negotiation-chat text, ransom-note text, wallet addresses or IOC lists. Upstream records are reduced to counts in memory during the Actions run. Only counts, CVE/tool mappings and links reach the repo and the site. A unit test enforces this by feeding victim names through the real fetch path and asserting none appear in the output or the stored state.

## Local development (maintainers only)

```bash
npm ci
npm run pipeline      # fetch + build data into web/public/data (state in ./state)
npm run dev           # dashboard at http://localhost:5173
npm test              # unit tests (parsing, sanitising, extraction, clustering, rules)
npm run typecheck
npm run check-feeds   # re-test every feed URL (add -- --all to include disabled ones)
```

## Editing feeds (maintainers only)

Edit [`config/feeds.yaml`](../config/feeds.yaml). Each feed has a tier (A advisory / B research / C news) and a group. Optional fields:

- `include` / `exclude` title regexes
- `firehose: true` for bulk advisory streams
- `marketing: false` to disable the vendor-marketing title filter
- custom `headers`

Dropped feeds are kept with `enabled: false` and a reason.

## Security

- Feed content is untrusted. The pipeline converts everything to plain text, and the UI never renders HTML.
- Only `http(s)` links are emitted; `javascript:`, `data:` and URLs with credentials are rejected.
- A strict Content-Security-Policy (`default-src 'self'`, no inline script or style) is injected at build time. The page makes no third-party requests.
- CSV exports neutralise spreadsheet formula injection.
- Workflows use least-privilege permissions per job, and actions are pinned to full commit SHAs. Dependabot keeps npm packages and actions current.
- Public PoC repositories are **counted, not linked**: many contain malware.

## Data sources & terms

| Source | Use | Terms |
|---|---|---|
| CISA Known Exploited Vulnerabilities | KEV status, due dates, ransomware flag | U.S. Government work |
| FIRST EPSS | exploit-probability scores, daily movers | Free to use; see first.org/epss |
| CVE Program cvelistV5 (incl. CISA-ADP / Vulnrichment) | CVSS, CWE, SSVC | CVE Terms of Use |
| nomi-sec/PoC-in-GitHub | public PoC first-seen dates (counts only) | CC0 |
| MISP galaxy (incl. MITRE ATT&CK clusters) | actor/malware/ransomware names and aliases, actor attribution & suspected victims | CC0 / BSD-2-Clause |
| Ransomware Vulnerability Matrix & Tool Matrix (Will Thomas) | CVE → ransomware group, tool → group | CC BY 4.0 (parsed and normalised) |
| CIRCL Vulnerability-Lookup | multi-catalogue KEV, exploitation sightings (counts), Rulezet rule counts | Per catalogue; CIRCL open data CC BY 4.0 |
| NIST NVD | analysis status, CPE count, CVSS fallback | Public domain; *uses NVD data but is not endorsed or certified by the NVD* |
| Nuclei templates, ET Open, SigmaHQ, YARA Forge | "detection exists" + links (no rule bodies) | MIT / BSD–GPLv2 / DRL 1.1 / GPL-3.0 |
| RansomLook | leak-site post counts per group and week | CC BY 4.0 |
| Ransomware.live (optional key) | claim counts per group, sector and country | Non-commercial use with attribution; no raw data republished |
| Cyberwatch (Valéry Rieß-Marchive) | publicly reported cyberattacks per country | CC BY-NC 4.0 |
| Ransomchats (Valéry Rieß-Marchive) | negotiation-chat counts per group | MIT |
| Zscaler ThreatLabz ransomware_notes | ransom-note sample counts per family | MIT |
| Ransomwhere (Jack Cable) | traced ransom payments per family | CC BY 4.0, doi:10.5281/zenodo.6512122 |
| Infostealers.com (Hudson Rock) | infostealer research (RSS) + lookup links | Publisher terms |
| Natural Earth via `world-atlas` | country outlines for the map (bundled, no external requests) | Public domain / ISC |
| `i18n-iso-countries` | country names and ISO codes for country extraction | MIT |
| Feeds in `config/feeds.yaml` | headlines, short summaries, links to the original | Each publisher's terms; CyberDigest links to every original article |

## License

MIT. See [LICENSE](../LICENSE).
