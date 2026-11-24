// CyberDigest pipeline: fetch → normalise → extract → enrich → cluster → score → publish JSON.
// Run with `npm run pipeline`. State lives in STATE_DIR (default ./state), output in OUT_DIR.

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  CveInfo,
  EnrichmentHealth,
  EpssMovers,
  FeedHealth,
  GroupRole,
  Health,
  KevEntry,
  Meta,
  SourceInfo,
  Story,
  StorySource,
} from '../../shared/types';
import { clusterItems, type ClusterInput } from './cluster';
import { CONFIG } from './config';
import { loadOrBuildDicts } from './dicts';
import { enrichCves, enrichPoc, type CveSummary, type PocSummary } from './enrich/cvelist';
import { epssApiLookup, updateEpss, type EpssScore } from './enrich/epss';
import { indexKev, trackRansomwareFlips, updateKev } from './enrich/kev';
import { claimsExploited, EntityMatcher, extractCves, extractEntities } from './extract';
import { keepTitle, loadFeeds, type FeedConfig } from './feeds';
import { decodeText, fetchRaw } from './fetch';
import { parseFeed } from './parse';
import { focalCves, scoreStory, type ScoreItem } from './score';
import { StateStore, type HttpCacheEntry } from './state';
import { canonicalUrl, clamp, titleTokens, toPlainText } from './text';
import { detectionCount, loadDetectionIndex } from './detections';
import { Circl } from './enrich/circl';
import { updateNvd } from './enrich/nvd';
import { updateEuvd } from './enrich/euvd';
import { updateOss } from './enrich/oss';
import { updateVulncheck, VULNCHECK_CATALOG } from './enrich/vulncheck';
import { extractCountries } from './geo';
import { buildRansomware } from './ransomware/activity';
import { GroupResolver } from './ransomware/aliases';
import { loadRtm, loadRvm } from './ransomware/matrices';
import { SourceRegistry } from './sources';
import type { Upstream } from './upstream';
import { buildActors, buildOverview } from './overview';
import { buildTrends } from './trends';
import { DAY, HOUR, errMsg, pool, shortHash } from './util';

export interface StoredItem {
  key: string;
  feedId: string;
  title: string;
  url: string;
  summary: string;
  published: string | null;
  firstSeen: string;
  cves: string[];
  vendors: string[];
  actors: string[];
  malware: string[];
  exploited: boolean;
}

interface FeedState {
  lastOk?: string;
  consecutiveFailures: number;
}

interface RunMeta {
  stateSince: string;
}

const TIER_RANK = { A: 0, B: 1, C: 2 } as const;

function itemTime(it: StoredItem): number {
  return Date.parse(it.published ?? it.firstSeen);
}

async function ingestFeed(
  feed: FeedConfig,
  ctx: {
    now: number;
    http: Record<string, HttpCacheEntry>;
    items: Record<string, StoredItem>;
    feedState: Record<string, FeedState>;
    matcher: EntityMatcher | null;
    /** Canonical article URL → owning item key (cross-feed de-duplication). */
    urlOwner: Map<string, string>;
    feedTier: (feedId: string) => FeedConfig['tier'];
  },
): Promise<FeedHealth> {
  const nowIso = new Date(ctx.now).toISOString();
  const fs = (ctx.feedState[feed.id] ??= { consecutiveFailures: 0 });
  const res = await fetchRaw(feed.url, { ...ctx.http[feed.id], headers: feed.headers });
  const health: FeedHealth = {
    id: feed.id,
    name: feed.name,
    url: feed.url,
    tier: feed.tier,
    group: feed.group,
    status: res.status,
    httpStatus: res.httpStatus,
    error: res.error,
    lastAttempt: nowIso,
    consecutiveFailures: 0,
    itemsPerWeek: 0,
    possibleGap: false,
    ms: res.ms,
    bytes: res.bytes,
  };

  if (res.status === 'ok' && res.data) {
    try {
      const entries = parseFeed(decodeText(res.data, res.contentType));
      const cutoff = ctx.now - CONFIG.retentionDays * DAY;
      let inWindow = 0;
      let known = 0;
      for (const e of entries) {
        const title = toPlainText(e.title);
        if (!keepTitle(feed, title)) continue;
        const url = canonicalUrl(e.link, feed.url) ?? canonicalUrl(e.guid);
        if (!url) continue;
        let published = e.published;
        if (published && Date.parse(published) > ctx.now + HOUR) published = null;
        const key = `${feed.id}:${shortHash(e.guid || url || title, 16)}`;
        const existing = ctx.items[key];
        if (existing) {
          known++;
          inWindow++;
          continue;
        }
        // The same article from an overlapping feed (e.g. a publisher's main feed and its ransomware
        // category feed) is one item, not two sources. The higher-tier feed owns it.
        const ownerKey = ctx.urlOwner.get(url);
        const owner = ownerKey ? ctx.items[ownerKey] : undefined;
        if (owner) {
          if (owner.feedId !== feed.id && TIER_RANK[feed.tier] < TIER_RANK[ctx.feedTier(owner.feedId)]) owner.feedId = feed.id;
          known++;
          inWindow++;
          continue;
        }
        const time = published ? Date.parse(published) : ctx.now;
        if (time < cutoff) continue;
        inWindow++;
        const body = toPlainText(e.body);
        const ents = extractEntities(ctx.matcher, title, body);
        ctx.urlOwner.set(url, key);
        ctx.items[key] = {
          key,
          feedId: feed.id,
          title: clamp(title, 300),
          url,
          summary: clamp(body, 320),
          published,
          firstSeen: nowIso,
          ...ents,
          exploited: claimsExploited(`${title}. ${body.slice(0, 600)}`),
        };
      }
      ctx.http[feed.id] = { etag: res.etag, lastModified: res.lastModified };
      health.possibleGap = Boolean(fs.lastOk) && inWindow >= 5 && known === 0;
      if (entries.length === 0) health.error = 'feed parsed but contains no items';
    } catch (e) {
      health.status = 'error';
      health.error = errMsg(e);
    }
  }

  if (health.status === 'error') {
    fs.consecutiveFailures++;
    delete ctx.http[feed.id];
  } else {
    fs.consecutiveFailures = 0;
    fs.lastOk = nowIso;
  }
  health.consecutiveFailures = fs.consecutiveFailures;
  health.lastOk = fs.lastOk;
  return health;
}

async function main(): Promise<void> {
  const started = Date.now();
  const now = started;
  const nowIso = new Date(now).toISOString();
  const store = new StateStore(CONFIG.paths.state);
  const feeds = loadFeeds();
  const active = feeds.filter((f) => f.enabled);
  const feedById = new Map(feeds.map((f) => [f.id, f]));

  const http = store.readJson<Record<string, HttpCacheEntry>>('http-cache.json', {});
  const items = store.readJson<Record<string, StoredItem>>('items.json', {});
  const feedState = store.readJson<Record<string, FeedState>>('feed-state.json', {});
  const runMeta = store.readJson<RunMeta>('run-meta.json', { stateSince: nowIso });
  const cveCache = store.readJson<Record<string, CveSummary>>('cve-cache.json', {});
  const pocCache = store.readJson<Record<string, PocSummary>>('poc-cache.json', {});
  const reg = new SourceRegistry(store.readJson<SourceInfo[]>('sources.json', []));
  const up: Upstream = { store, http, gates: store.readJson<Record<string, string>>('gates.json', {}), now };
  const fromHealth = (id: string, h: EnrichmentHealth, retrieved = true) => reg.set(id, { status: h.status, detail: h.detail, retrieved: retrieved && h.status === 'ok' });

  // 1. KEV first: the dictionary build uses KEV vendor names.
  const kev = await updateKev(store, http);
  fromHealth('cisa-kev', kev.health);
  reg.set('cisa-kev', { version: kev.catalog?.catalogVersion ?? null });
  const kevIndex = indexKev(kev.catalog);
  const flips = trackRansomwareFlips(store, kev.catalog, now);

  // 2. Entity dictionary (weekly).
  const dicts = await loadOrBuildDicts(store.dir);
  reg.set('misp-galaxy', {
    status: dicts.dict ? (dicts.error ? 'stale' : 'ok') : 'error',
    detail: dicts.dict
      ? `${dicts.dict.actors.length} actors, ${dicts.dict.malware.length} malware, ${dicts.dict.ransomware?.length ?? 0} ransomware, ${dicts.dict.vendors.length} vendors; built ${dicts.dict.builtAt.slice(0, 10)}${dicts.rebuilt ? ' (rebuilt this run)' : ''}${dicts.error ? `; rebuild failed: ${dicts.error}` : ''}`
      : `unavailable: ${dicts.error}`,
    version: dicts.dict?.builtAt.slice(0, 10) ?? null,
    retrieved: dicts.rebuilt,
  });
  const matcher = dicts.dict ? new EntityMatcher(dicts.dict) : null;
  const resolver = GroupResolver.fromConfig(undefined, dicts.dict?.ransomware ?? []);

  // 2b. Ransomware matrices (daily): their CVEs join the tracked set below.
  const [rvm, rtm] = await Promise.all([loadRvm(up, reg), loadRtm(up, reg)]);
  const rvmByCve = new Map<string, { name: string; role: GroupRole }[]>();
  for (const row of rvm.rows) {
    for (const cve of row.cves) {
      const list = rvmByCve.get(cve) ?? [];
      for (const g of row.groups) {
        const name = resolver.resolve(g.name).name;
        if (!list.some((x) => x.name === name)) list.push({ name, role: g.role });
      }
      rvmByCve.set(cve, list);
    }
  }

  // 3. Feeds.
  const urlOwner = new Map<string, string>();
  for (const [k, it] of Object.entries(items)) {
    const prev = urlOwner.get(it.url);
    // Collapse duplicates already in state (keep the higher-tier copy).
    if (prev && items[prev] && feedById.has(it.feedId) && feedById.has(items[prev]!.feedId)) {
      const keepNew = TIER_RANK[feedById.get(it.feedId)!.tier] < TIER_RANK[feedById.get(items[prev]!.feedId)!.tier];
      delete items[keepNew ? prev : k];
      if (keepNew) urlOwner.set(it.url, k);
      continue;
    }
    urlOwner.set(it.url, k);
  }
  const feedTier = (id: string) => feedById.get(id)?.tier ?? 'C';
  const feedHealth = await pool(active, CONFIG.fetch.concurrency, (f) => ingestFeed(f, { now, http, items, feedState, matcher, urlOwner, feedTier }));

  // 4. Retention.
  const cutoff = now - CONFIG.retentionDays * DAY;
  for (const [k, it] of Object.entries(items)) {
    if (itemTime(it) < cutoff || !feedById.get(it.feedId)?.enabled) delete items[k];
  }
  const all = Object.values(items);
  for (const h of feedHealth) {
    h.itemsPerWeek = all.filter((i) => i.feedId === h.id && itemTime(i) >= now - 7 * DAY).length;
    const newest = all.filter((i) => i.feedId === h.id).reduce((m, i) => Math.max(m, itemTime(i)), 0);
    if (newest) h.newestItem = new Date(newest).toISOString();
  }

  // 5. CVE enrichment for every CVE in the window plus recent KEV additions.
  const mentioned = new Set(all.flatMap((i) => i.cves));
  const recentKev = (kev.catalog?.vulnerabilities ?? []).filter((v) => Date.parse(v.dateAdded) >= cutoff).map((v) => v.cveID);
  const trackedSet = new Set([...mentioned, ...recentKev, ...rvmByCve.keys()]);
  for (const k of Object.keys(cveCache)) if (!trackedSet.has(k)) delete cveCache[k];
  for (const k of Object.keys(pocCache)) if (!trackedSet.has(k)) delete pocCache[k];

  const epss = await updateEpss(store, http);
  let epssScores: Map<string, EpssScore> = epss.data.scores;
  if (epssScores.size === 0 && trackedSet.size) epssScores = await epssApiLookup([...trackedSet].slice(0, 600));

  // Per-run fetch budgets are limited, so enrich what matters first:
  // KEV → CVEs named by non-firehose sources → high EPSS → the rest (newest IDs first).
  const curatedCves = new Set(all.filter((i) => !feedById.get(i.feedId)?.firehose).flatMap((i) => i.cves));
  const importance = (id: string) =>
    kevIndex.has(id) ? 0 : curatedCves.has(id) || rvmByCve.has(id) ? 1 : (epssScores.get(id)?.epss ?? 0) >= CONFIG.rules.epssHigh ? 2 : 3;
  const tracked = [...trackedSet].sort((a, b) => importance(a) - importance(b) || b.localeCompare(a, 'en', { numeric: true }));
  const circl = new Circl(up);
  const [cveHealth, pocHealth, nvd, detIndex, , euvd, oss, vulncheck] = await Promise.all([
    enrichCves(tracked, cveCache),
    enrichPoc(tracked, pocCache),
    updateNvd(up, trackedSet, reg),
    loadDetectionIndex(up, reg),
    (async () => {
      await circl.updateKev(reg);
      await circl.updateSightings(reg);
    })(),
    updateEuvd(up, trackedSet, reg),
    updateOss(up, tracked, reg),
    updateVulncheck(up, reg),
  ]);
  fromHealth('epss', epss.health, true);
  reg.set('epss', { version: epss.data.model });
  fromHealth('cvelist', cveHealth);
  fromHealth('poc', pocHealth);

  const cveInfoCache = new Map<string, CveInfo>();
  const cveInfo = (id: string): CveInfo | undefined => {
    if (cveInfoCache.has(id)) return cveInfoCache.get(id);
    const rec = cveCache[id];
    const k = kevIndex.get(id);
    const s = epssScores.get(id);
    const p = pocCache[id];
    const groups = rvmByCve.get(id);
    const n = nvd.get(id);
    const exploitation = circl.exploitation(id, Boolean(k), vulncheck.has(id) ? [VULNCHECK_CATALOG] : []);
    const o = oss.get(id);
    if (!rec && !k && !s && !groups && !exploitation) return undefined;
    const prev = epss.data.prev.get(id);
    const det = detIndex?.cves[id];
    const flippedAt = flips.get(id);
    const info: CveInfo = {
      id,
      description: rec?.description,
      published: rec?.published,
      state: rec?.state,
      cvss: rec?.cvss ?? n?.cvss,
      cvssVersion: rec?.cvss != null ? rec.cvssVersion : n?.cvss != null ? 'NVD' : undefined,
      severity: rec?.severity,
      cwe: rec?.cwe,
      vendor: rec?.vendor ?? k?.vendorProject,
      product: rec?.product ?? k?.product,
      kev: k
        ? {
            dateAdded: k.dateAdded,
            dueDate: k.dueDate,
            ransomware: k.knownRansomwareCampaignUse === 'Known',
            name: k.vulnerabilityName,
            requiredAction: k.requiredAction,
          }
        : undefined,
      epss: s?.epss ?? null,
      epssPct: s?.pct ?? null,
      epssDelta: s && epss.data.prevDate ? Math.round((s.epss - (prev?.epss ?? s.epss)) * 1e5) / 1e5 : null,
      ssvc: rec?.ssvc,
      poc: p && p.count > 0 ? { count: p.count, firstSeen: p.firstSeen ?? p.fetchedAt } : undefined,
      ransomware:
        k?.knownRansomwareCampaignUse === 'Known' || groups?.length
          ? { kevKnown: k?.knownRansomwareCampaignUse === 'Known', ...(flippedAt ? { flippedAt } : {}), groups: groups ?? [] }
          : undefined,
      exploitation,
      detections: det ? { ...det, ...(circl.rulezetCount(id) !== undefined ? { rulezet: circl.rulezetCount(id) } : {}) } : undefined,
      nvd: n ? { status: n.status, cpes: n.cpes } : undefined,
      euvd: euvd.get(id),
      oss: o && (o.ghsa || o.osv || o.packages.length) ? { ...(o.ghsa ? { ghsa: o.ghsa } : {}), packages: o.packages, osv: o.osv, related: o.related } : undefined,
      stories: [],
      sources: 0,
      firstSeen: '',
      lastSeen: '',
    };
    cveInfoCache.set(id, info);
    return info;
  };

  // 6. Cluster + score.
  const inputs: ClusterInput[] = all.map((it) => ({
    feedId: it.feedId,
    time: itemTime(it),
    cves: it.cves,
    titleCves: extractCves(it.title),
    entities: new Set([...it.vendors, ...it.actors, ...it.malware].map((e) => e.toLowerCase())),
    tokens: titleTokens(it.title),
  }));
  const groups = clusterItems(inputs);
  const itemCountries = new Map(all.map((it) => [it.key, extractCountries(`${it.title}. ${it.summary}`)]));

  const allStories: (Story & { start: number })[] = groups.map((g) => {
    const members = g.map((i) => all[i]!);
    members.sort((a, b) => {
      const fa = feedById.get(a.feedId)!;
      const fb = feedById.get(b.feedId)!;
      return TIER_RANK[fa.tier] - TIER_RANK[fb.tier] || Number(fa.firehose) - Number(fb.firehose) || itemTime(a) - itemTime(b);
    });
    const lead = members[0]!;
    const leadFeed = feedById.get(lead.feedId)!;
    const times = members.map(itemTime);
    const scoreItems: ScoreItem[] = members.map((m) => {
      const f = feedById.get(m.feedId)!;
      return {
        feedId: m.feedId,
        tier: f.tier,
        firehose: f.firehose,
        time: itemTime(m),
        exploited: m.exploited,
        cves: m.cves,
        focalCves: focalCves(m.cves, extractCves(m.title)),
        hasThreatEntity: m.actors.length + m.malware.length > 0,
      };
    });
    const { priority, reasons } = scoreStory(scoreItems, cveInfo, now);
    const sources: StorySource[] = members.slice(1, 80).map((m) => {
      const f = feedById.get(m.feedId)!;
      return { feedId: f.id, feed: f.name, tier: f.tier, title: m.title, url: m.url, date: new Date(itemTime(m)).toISOString() };
    });
    // Entities ordered by how many member items mention them; in larger clusters, drop
    // one-off mentions (a single article's aside shouldn't tag the whole story).
    const union = (pick: (m: StoredItem) => string[]) => {
      const counts = new Map<string, number>();
      for (const m of members) for (const e of new Set(pick(m))) counts.set(e, (counts.get(e) ?? 0) + 1);
      const minCount = members.length >= 4 ? 2 : 1;
      return [...counts.entries()]
        .filter(([e, n]) => n >= minCount || pick(lead).includes(e))
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([e]) => e);
    };
    return {
      id: shortHash(lead.key),
      title: lead.title,
      url: lead.url,
      summary: lead.summary || members.find((m) => m.summary)?.summary || '',
      feedId: leadFeed.id,
      feed: leadFeed.name,
      tier: leadFeed.tier,
      group: leadFeed.group,
      date: new Date(Math.min(...times)).toISOString(),
      leadDate: new Date(itemTime(lead)).toISOString(),
      firstSeen: members.map((m) => m.firstSeen).sort()[0]!,
      lastSeen: new Date(Math.max(...times)).toISOString(),
      priority,
      reasons,
      sources,
      sourceCount: new Set(members.map((m) => m.feedId)).size,
      // CVEs: all of them (the copy-list needs every ID), headline/focal ones first, then newest.
      cves: [...new Set([...extractCves(lead.title), ...members.flatMap((m) => extractCves(m.title)), ...members.flatMap((m) => m.cves).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }))])],
      vendors: union((m) => m.vendors),
      actors: union((m) => m.actors),
      malware: union((m) => m.malware),
      countries: union((m) => itemCountries.get(m.key) ?? []),
      exploited: members.some((m) => m.exploited),
      start: Math.min(...times),
    };
  });

  const storyCutoff = now - CONFIG.storyWindowDays * DAY;
  const stories: Story[] = allStories
    .filter((s) => Date.parse(s.lastSeen) >= storyCutoff)
    .sort(
      (a, b) =>
        a.priority - b.priority ||
        b.lastSeen.slice(0, 10).localeCompare(a.lastSeen.slice(0, 10)) ||
        b.sourceCount - a.sourceCount ||
        b.lastSeen.localeCompare(a.lastSeen),
    )
    .map(({ start: _start, ...s }) => s);
  const windowItems = all.filter((i) => itemTime(i) >= storyCutoff).length;

  // 6b. Rulezet top-up for hot CVEs (P1/P2 stories) the repo index doesn't cover, then detection gaps.
  const hot = [...new Set(stories.filter((s) => s.priority <= 2).flatMap((s) => s.cves.slice(0, 5)))].filter((id) => detectionCount(cveInfo(id)?.detections) === 0);
  await circl.updateRulezet(hot, reg, 6);
  for (const id of hot) {
    const info = cveInfo(id);
    const n = circl.rulezetCount(id);
    if (info && n !== undefined) info.detections = { ...(info.detections ?? { sigma: [], et: [], yara: [] }), rulezet: n };
  }
  if (detIndex) {
    for (const info of cveInfoCache.values()) {
      const exploited = Boolean(info.kev) || Boolean(info.exploitation?.catalogs.length) || (info.exploitation?.exploited30d ?? 0) > 0;
      if (exploited) info.detectionGap = detectionCount(info.detections) === 0 && !(info.detections?.rulezet ?? 0);
    }
  }

  // 7. CVE table.
  const storiesByCve = new Map<string, string[]>();
  for (const s of stories) for (const c of s.cves) storiesByCve.set(c, [...(storiesByCve.get(c) ?? []), s.id]);
  const cves: CveInfo[] = [];
  for (const id of mentioned) {
    const base = cveInfo(id) ?? { id, epss: null, epssPct: null, epssDelta: null, stories: [], sources: 0, firstSeen: '', lastSeen: '' };
    const its = all.filter((i) => i.cves.includes(id));
    const times = its.map(itemTime);
    cves.push({
      ...base,
      stories: storiesByCve.get(id) ?? [],
      sources: new Set(its.map((i) => i.feedId)).size,
      firstSeen: new Date(Math.min(...times)).toISOString(),
      lastSeen: new Date(Math.max(...times)).toISOString(),
    });
  }
  cves.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));

  // 8. KEV + EPSS movers.
  const kevEntries: KevEntry[] = [...(kev.catalog?.vulnerabilities ?? [])]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID))
    .slice(0, 50)
    .map((v) => {
      const s = epssScores.get(v.cveID);
      return {
        cve: v.cveID,
        vendor: v.vendorProject,
        product: v.product,
        name: v.vulnerabilityName,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        ransomware: v.knownRansomwareCampaignUse === 'Known',
        requiredAction: v.requiredAction,
        shortDescription: v.shortDescription,
        epss: s?.epss ?? null,
        epssPct: s?.pct ?? null,
        stories: storiesByCve.get(v.cveID)?.length ?? 0,
      };
    });
  const movers: EpssMovers = {
    date: epss.data.date,
    prevDate: epss.data.prevDate,
    movers: epss.data.movers
      .map((m) => ({ ...m, kev: kevIndex.has(m.cve), stories: storiesByCve.get(m.cve)?.length ?? 0 }))
      .sort((a, b) => Number(b.stories > 0) - Number(a.stories > 0) || Number(b.kev) - Number(a.kev))
      .slice(0, 100),
    modelChange: epss.data.modelChange,
  };

  // 9. Trends.
  const historyDays = Math.floor((now - Date.parse(runMeta.stateSince)) / DAY) + 1;
  const trends = buildTrends(allStories.map((s) => ({ time: s.start, actors: s.actors, malware: s.malware, vendors: s.vendors })), now, historyDays);

  // 10. Overview aggregates + actor profiles.
  const cveById = new Map(cves.map((c) => [c.id, c]));
  const overviewInput = {
    now,
    allStories,
    stories,
    cveInfo: (id: string) => cveById.get(id) ?? cveInfo(id),
    kev: kev.catalog,
    items: all.map((i) => ({ feedGroup: feedById.get(i.feedId)!.group, time: itemTime(i) })),
    actorDict: new Map((dicts.dict?.actors ?? []).map((a) => [a.name, a])),
    trendDays: trends.days,
  };
  // 10b. Ransomware activity, group profiles, KEV flips, hunting tools (counts and links only).
  const ransomware = await buildRansomware({
    u: up,
    reg,
    resolver,
    rvm,
    rtm,
    mispRansomware: dicts.dict?.ransomware ?? [],
    kevIndex,
    flips,
    cveInfo: (id) => cveById.get(id) ?? cveInfo(id),
  });
  const overview = buildOverview({ ...overviewInput, ransomCountries: ransomware.countries });
  const actors = buildActors(overviewInput);

  // 11. Write.
  const feedsFailed = feedHealth.filter((h) => h.status === 'error').length;
  reg.set('feeds', { status: feedsFailed > feedHealth.length / 4 ? 'stale' : 'ok', detail: `${feedHealth.length - feedsFailed}/${feedHealth.length} feeds OK`, retrieved: true });
  reg.set('natural-earth', { status: 'ok', detail: 'Bundled with the site' });
  const sources = reg.all();
  const health: Health = {
    feeds: feedHealth.sort((a, b) => Number(b.status === 'error') - Number(a.status === 'error') || a.name.localeCompare(b.name)),
    enrichment: sources.filter((s) => s.use !== 'link' && s.id !== 'feeds' && s.id !== 'natural-earth').map((s) => ({ name: s.name, status: s.status, detail: s.detail })),
  };
  const meta: Meta = {
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    stateSince: runMeta.stateSince,
    repo: CONFIG.repo,
    counts: {
      items: windowItems,
      stories: stories.length,
      collapsed: Math.max(0, windowItems - stories.length),
      cves: cves.length,
      feedsOk: feedHealth.length - feedsFailed,
      feedsFailed,
      feedsTotal: feedHealth.length,
    },
    data: {
      kevCatalogVersion: kev.catalog?.catalogVersion ?? null,
      kevCount: kev.catalog?.count ?? 0,
      epssDate: epss.data.date,
      epssModel: epss.data.model,
    },
  };

  mkdirSync(CONFIG.paths.out, { recursive: true });
  const out = (name: string, data: unknown) => writeFileSync(join(CONFIG.paths.out, name), JSON.stringify(data));
  out('stories.json', stories);
  out('cves.json', cves);
  out('kev.json', kevEntries);
  out('epss.json', movers);
  out('trends.json', trends);
  out('health.json', health);
  out('overview.json', overview);
  out('actors.json', actors);
  out('ransomware.json', ransomware.data);
  out('sources.json', sources);
  out('meta.json', meta);

  circl.save();
  store.writeJson('sources.json', sources);
  store.writeJson('gates.json', up.gates, true);
  store.writeJson('items.json', items);
  store.writeJson('http-cache.json', http, true);
  store.writeJson('feed-state.json', feedState, true);
  store.writeJson('run-meta.json', runMeta, true);
  store.writeJson('cve-cache.json', cveCache);
  store.writeJson('poc-cache.json', pocCache);

  const byP = [1, 2, 3, 4].map((p) => stories.filter((s) => s.priority === p).length);
  console.log(
    [
      `CyberDigest pipeline finished in ${((Date.now() - started) / 1000).toFixed(1)}s`,
      `feeds: ${meta.counts.feedsOk}/${meta.counts.feedsTotal} ok`,
      `items (14d): ${windowItems} → stories: ${stories.length} (P1 ${byP[0]} · P2 ${byP[1]} · P3 ${byP[2]} · P4 ${byP[3]})`,
      `CVEs: ${cves.length} · KEV ${meta.data.kevCount} · EPSS ${meta.data.epssDate ?? 'n/a'}`,
      `ransomware: ${ransomware.data.groups.length} group profiles · ${ransomware.data.rvmCves.length} RVM CVEs · ${ransomware.data.kevFlips.length} KEV flips`,
      ...sources.filter((s) => s.use !== 'link').map((e) => `  ${e.status.padEnd(7)} ${e.name}: ${e.detail}`),
      ...feedHealth.filter((h) => h.status === 'error').map((h) => `  FAIL  ${h.id}: ${h.error}`),
    ].join('\n'),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
