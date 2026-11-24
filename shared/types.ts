// Data contract between the pipeline (writer) and the dashboard (reader).
// Every JSON file under /data/ conforms to one of these shapes.

export type SourceTier = 'A' | 'B' | 'C';
export type Priority = 1 | 2 | 3 | 4;
export type FeedGroup = 'intel' | 'vuln' | 'gov' | 'psirt' | 'news' | 'blue';

export const GROUP_LABELS: Record<FeedGroup, string> = {
  intel: 'Threat research',
  vuln: 'Vuln research',
  gov: 'Government / CERT',
  psirt: 'Vendor PSIRT',
  news: 'News',
  blue: 'Blue team',
};

export const PRIORITY_LABELS: Record<Priority, string> = {
  1: 'Act now',
  2: 'High',
  3: 'Monitor',
  4: 'Context',
};

export interface Meta {
  generatedAt: string;
  durationMs: number;
  stateSince: string;
  repo: string | null;
  counts: {
    items: number;
    stories: number;
    collapsed: number;
    cves: number;
    feedsOk: number;
    feedsFailed: number;
    feedsTotal: number;
  };
  data: {
    kevCatalogVersion: string | null;
    kevCount: number;
    epssDate: string | null;
    epssModel: string | null;
  };
}

/** Machine code + human label for each rule that fired. */
export interface Reason {
  code:
    | 'kev-new'
    | 'kev'
    | 'kev-ransom'
    | 'ssvc-active'
    | 'exploited-advisory'
    | 'exploited-claim'
    | 'epss-high'
    | 'epss-jump'
    | 'poc-new'
    | 'multi-source'
    | 'advisory'
    | 'research'
    | 'ransomware-linked'
    | 'kev-ransom-flip'
    | 'exploited-multi'
    | 'honeypot';
  label: string;
  cve?: string;
}

export interface StorySource {
  feedId: string;
  feed: string;
  tier: SourceTier;
  title: string;
  url: string;
  date: string;
}

export interface Story {
  id: string;
  title: string;
  url: string;
  summary: string;
  feedId: string;
  feed: string;
  tier: SourceTier;
  group: FeedGroup;
  date: string;
  /** Publication time of the lead article itself (date = earliest article in the story). */
  leadDate?: string;
  firstSeen: string;
  lastSeen: string;
  priority: Priority;
  reasons: Reason[];
  /** Other items in this cluster (the lead is described by the fields above). */
  sources: StorySource[];
  sourceCount: number;
  cves: string[];
  vendors: string[];
  actors: string[];
  malware: string[];
  /** ISO alpha-2 codes of countries named in the story's headlines/summaries. */
  countries: string[];
  exploited: boolean;
}

export interface Named {
  name: string;
  count: number;
}

export interface ActorProfile {
  name: string;
  aliases: string[];
  /** Suspected origin / sponsor (ISO alpha-2), from MISP galaxy attribution. */
  country: string | null;
  countryName: string | null;
  countryNumeric: string | null;
  /** Suspected victim countries from the actor's MISP profile (reference data, not live incidents). */
  targets: { iso: string; name: string; numeric: string | null }[];
  sectors: string[];
  motive: string | null;
  description: string | null;
  /** Published story ids mentioning the actor, newest first. */
  stories: string[];
  /** Stories per day over the trend window (aligned with Trends.days). */
  days: number[];
  last7: number;
  total30: number;
  malware: Named[];
  vendors: Named[];
  cves: string[];
  lastSeen: string;
}

export interface CountryStat {
  iso: string;
  /** ISO numeric (Natural Earth / world-atlas geometry id). */
  numeric: string | null;
  name: string;
  /** Stories (14d) naming this country. */
  news: number;
  /** Stories (14d) mentioning an actor attributed to this country. */
  origin: number;
  /** Actors active in the last 14 days whose profile lists this country as a target. */
  targeted: number;
  /** Ransomware leak-site claims (ransomware.live) or publicly reported attacks (Cyberwatch), 30 days. */
  ransom: number;
  newsStories: string[];
  originActors: string[];
  targetActors: string[];
}

export interface Overview {
  days: string[];
  /** Stories first reported per day by priority [P1, P2, P3, P4]. */
  priorityByDay: { day: string; p: [number, number, number, number] }[];
  kevByWeek: { week: string; total: number; ransomware: number }[];
  vendors: { name: string; stories: number; high: number; kev: number }[];
  cwes: { id: string; name: string; count: number }[];
  severity: { label: string; count: number }[];
  epssBins: { label: string; count: number }[];
  groups: { group: FeedGroup; items: number; stories: number }[];
  countries: CountryStat[];
  tiles: {
    p1: [number, number];
    kev: [number, number];
    stories: [number, number];
    exploitedCves: [number, number];
  };
}

export interface CveInfo {
  id: string;
  description?: string;
  published?: string;
  state?: string;
  cvss?: number;
  cvssVersion?: string;
  severity?: string;
  cwe?: string[];
  vendor?: string;
  product?: string;
  kev?: {
    dateAdded: string;
    dueDate: string;
    ransomware: boolean;
    name: string;
    requiredAction: string;
  };
  /** null = no EPSS score yet (render as "n/a", never as 0). */
  epss: number | null;
  epssPct: number | null;
  epssDelta: number | null;
  ssvc?: { exploitation?: string; automatable?: string; technicalImpact?: string };
  poc?: { count: number; firstSeen: string };
  /** CISA KEV ransomware flag + groups from the Ransomware Vulnerability Matrix (Will Thomas, CC BY 4.0). */
  ransomware?: {
    kevKnown: boolean;
    /** When CISA flipped knownRansomwareCampaignUse from Unknown to Known (if observed). */
    flippedAt?: string;
    groups: { name: string; role: GroupRole }[];
  };
  /** Multi-source exploitation evidence: CIRCL Vulnerability-Lookup catalogues + sightings, and VulnCheck KEV. */
  exploitation?: {
    catalogs: string[];
    notInCisa: boolean;
    exploited30d: number;
    poc30d: number;
    honeypot7d: boolean;
  };
  /** Public detection content (existence + links only). */
  detections?: Detections;
  /** Exploited (KEV / CIRCL) but no public detection found in the indexed repositories. */
  detectionGap?: boolean;
  nvd?: { status: string; cpes: number };
  /** ENISA EUVD identifier (EUVD-YYYY-N). */
  euvd?: string;
  /** Open-source package data: GitHub Advisory Database (reviewed) + OSV.dev. */
  oss?: {
    ghsa?: string;
    packages: { ecosystem: string; name: string; fixed?: string }[];
    /** An OSV.dev record exists for this CVE. */
    osv: boolean;
    /** Related advisories listed by OSV (distro / ecosystem advisories). */
    related: number;
  };
  stories: string[];
  sources: number;
  firstSeen: string;
  lastSeen: string;
}

export type GroupRole = 'operator' | 'affiliate' | 'broker' | 'state';

export interface Detections {
  /** Nuclei template path in projectdiscovery/nuclei-templates. */
  nuclei?: string;
  sigma: { title: string; path: string }[];
  et: { sid: number; msg: string }[];
  yara: string[];
  /** Rule count from CIRCL Rulezet (checked for hot CVEs only). */
  rulezet?: number;
}

export interface SourceInfo {
  id: string;
  name: string;
  url: string;
  license: string;
  /** Credit line shown under widgets and on the credits page. */
  credit: string;
  /** What CyberDigest does with it (required by CC BY). */
  changes: string;
  use: 'data' | 'aggregate' | 'link';
  status: 'ok' | 'stale' | 'error' | 'skipped';
  detail: string;
  retrievedAt: string | null;
  version: string | null;
}

export interface RansomGroupProfile {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  /** Leak-site claims per week (RansomLook), aligned with RansomwareData.weeks. */
  weekly: number[];
  /** Same from ransomware.live PRO, when configured. */
  weeklyRl: number[] | null;
  last7: number;
  last30: number;
  cves: { id: string; role: GroupRole; product: string; vendor: string; sources: string[] }[];
  tools: { name: string; category: string }[];
  notes: number;
  chats: number;
  payments: { count: number; usd: number; last: string | null } | null;
  links: { label: string; url: string }[];
}

export interface RansomwareData {
  weeks: string[];
  caveat: string;
  totals: {
    ransomlook: { last7: number; prev7: number; groups7: number; groupsPrev7: number } | null;
    ransomwareLive: { last7: number; prev7: number; groups7: number; groupsPrev7: number } | null;
  };
  weekly: { ransomlook: number[] | null; ransomwareLive: number[] | null };
  annotations: { week: string; group: string; share: number }[];
  sectors: Named[];
  countries: { iso: string; name: string; numeric: string | null; count: number }[];
  countrySource: 'ransomware.live' | 'cyberwatch' | null;
  groups: RansomGroupProfile[];
  kevFlips: { cve: string; date: string; vendor: string; product: string; name: string }[];
  hunting: { category: string; tools: { name: string; groups: string[] }[] }[];
  rvmCves: {
    cve: string;
    groups: string[];
    product: string;
    vendor: string;
    kev: boolean;
    kevRansomware: boolean;
    epss: number | null;
    epssPct: number | null;
    cvss: number | null;
    detections: number;
  }[];
  matrixUpdated: { rvm: string | null; rtm: string | null };
}

export interface KevEntry {
  cve: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  requiredAction: string;
  shortDescription: string;
  epss: number | null;
  epssPct: number | null;
  stories: number;
}

export interface EpssMover {
  cve: string;
  epss: number;
  pct: number;
  prevEpss: number | null;
  prevPct: number | null;
  delta: number | null;
  kind: 'jump' | 'cross-p99' | 'cross-p95';
  kev: boolean;
  stories: number;
}

export interface EpssMovers {
  date: string | null;
  prevDate: string | null;
  movers: EpssMover[];
  /** Set when the EPSS model version changed between snapshots: movers are suppressed that day. */
  modelChange: { from: string; to: string; date: string } | null;
}

export interface TrendSeries {
  name: string;
  kind: 'actor' | 'malware' | 'vendor';
  /** Story counts per day, oldest → newest, aligned with Trends.days. */
  days: number[];
  last7: number;
  /** Expected 7-day count from the prior 23 days (null while history is too short). */
  baseline: number | null;
  rising: boolean;
}

export interface Trends {
  days: string[];
  historyDays: number;
  actors: TrendSeries[];
  malware: TrendSeries[];
  vendors: TrendSeries[];
}

export interface FeedHealth {
  id: string;
  name: string;
  url: string;
  tier: SourceTier;
  group: FeedGroup;
  status: 'ok' | 'not-modified' | 'error';
  httpStatus?: number;
  error?: string;
  lastOk?: string;
  lastAttempt: string;
  consecutiveFailures: number;
  itemsPerWeek: number;
  newestItem?: string;
  possibleGap: boolean;
  ms?: number;
  bytes?: number;
}

export interface EnrichmentHealth {
  name: string;
  status: 'ok' | 'stale' | 'error' | 'skipped';
  detail: string;
}

export interface Health {
  feeds: FeedHealth[];
  enrichment: EnrichmentHealth[];
}
