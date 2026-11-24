// All tunable thresholds live here so the ranking can be adjusted in one place.

const repo = process.env.GITHUB_REPOSITORY ?? null;
const server = process.env.GITHUB_SERVER_URL ?? 'https://github.com';

export const CONFIG = {
  repo,
  /** Honest bot UA. Several sites (Huntress, Fortinet) block spoofed browser UAs. */
  userAgent: `CyberDigest/1.0 (+${repo ? `${server}/${repo}` : 'https://github.com/'}; feed aggregator)`,

  paths: {
    feeds: 'config/feeds.yaml',
    state: process.env.STATE_DIR ?? 'state',
    out: process.env.OUT_DIR ?? 'web/public/data',
  },

  fetch: {
    timeoutMs: 20_000,
    concurrency: 8,
    maxBytes: 16 * 1024 * 1024,
  },

  /** Items older than this are discarded from state. Trends use the full window. */
  retentionDays: 30,
  /** Stories older than this are not published to stories.json. */
  storyWindowDays: 14,

  cluster: {
    /** Two items' CVE sets must overlap at least this much (Jaccard) to link, unless the CVE is in both headlines. */
    cveSetJaccard: 0.5,
    /** Title token Jaccard needed when the items also share an entity. */
    titleJaccardWithEntity: 0.4,
    /** Title token Jaccard needed with no shared entity. */
    titleJaccardAlone: 0.6,
    windowHours: 72,
  },

  rules: {
    kevNewDays: 7,
    /** KEV entries added within this many days raise a story to P2; older ones to P3. */
    kevRecentForHighDays: 365,
    /** SSVC Exploitation=active makes a story P1 only for CVEs published within this many days. */
    ssvcActiveUrgentDays: 30,
    /** A CISA KEV Unknown→Known ransomware flip stays a P2 signal for this many days. */
    kevFlipDays: 30,
    kevRansomDueDays: 14,
    /** EPSS ≥ 0.088 AND CVSS ≥ 7 (arXiv 2506.01220 rule). */
    epssHigh: 0.088,
    cvssHigh: 7,
    epssJump: 0.1,
    pocNewHours: 72,
    multiSourceCount: 3,
    multiSourceWindowHours: 24,
  },

  enrich: {
    /** Max per-CVE record fetches per run (cvelistV5 + PoC-in-GitHub each). */
    maxFetchPerRun: 200,
    cveTtlHours: 24,
    pocTtlHours: 12,
    dictMaxAgeDays: 7,
  },

  /** Headlines matching this are never dropped as marketing ("Git security vulnerabilities announced"). */
  securitySignal: /\b(vulnerabilit(y|ies)|CVE-\d{4}|zero-day|0-day|exploit(ed|s|ation)?|ransomware|breach(ed|es)?|malware|backdoor(s|ed)?)\b/i,
  /** Titles matching this are dropped from tier B/C feeds (vendor marketing), unless securitySignal matches. */
  marketingExclude:
    /\b(webinar|press release|launch(es|ed)?|announc(es|ed|ing)|award(s|ed)?|recogni[sz]ed|named a leader|gartner|forrester|idc marketscape|customer stor(y|ies)|partner(s|ship)|now available|introducing|join us|register now|event recap|podcast|hiring|careers|black friday|cyber monday|year in review|trust center|product update|release notes|what'?s new in)\b/i,

  urls: {
    kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    epssCsv: [
      'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
      'https://epss.cyentia.com/epss_scores-current.csv.gz',
    ],
    epssApi: 'https://api.first.org/data/v1/epss',
    cvelist: 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves',
    poc: 'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master',
    mispGalaxy: [
      'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters',
      'https://raw.githubusercontent.com/MISP/misp-galaxy/master/clusters',
    ],
  },
} as const;
