import { describe, expect, it } from 'vitest';
import type { CveInfo } from '../../shared/types';
import { epssLabel, focalCves, scoreStory, type ScoreItem } from '../src/score';

const NOW = Date.parse('2026-11-23T12:00:00Z');
const DAY = 86_400_000;
const iso = (daysAgo: number) => new Date(NOW - daysAgo * DAY).toISOString();

function cve(id: string, extra: Partial<CveInfo> = {}): CveInfo {
  return { id, epss: null, epssPct: null, epssDelta: null, stories: [], sources: 0, firstSeen: '', lastSeen: '', published: iso(10), ...extra };
}

function it_(over: Partial<ScoreItem> = {}): ScoreItem {
  const cves = over.cves ?? [];
  return { feedId: 'f1', tier: 'C', firehose: false, time: NOW - DAY, exploited: false, cves, focalCves: cves, hasThreatEntity: false, ...over };
}

const lookup = (list: CveInfo[]) => (id: string) => list.find((c) => c.id === id);
const kev = (daysAgo: number, ransomware = false, dueInDays = 21) => ({
  dateAdded: iso(daysAgo).slice(0, 10),
  dueDate: new Date(NOW + dueInDays * DAY).toISOString().slice(0, 10),
  ransomware,
  name: 'x',
  requiredAction: 'patch',
});

describe('scoreStory', () => {
  it('P1 for a CVE added to KEV within 7 days', () => {
    const r = scoreStory([it_({ cves: ['CVE-2026-1'] })], lookup([cve('CVE-2026-1', { kev: kev(2) })]), NOW);
    expect(r.priority).toBe(1);
    expect(r.reasons[0]).toMatchObject({ code: 'kev-new', label: 'KEV +2d', cve: 'CVE-2026-1' });
  });

  it('caps KEV-new at P2 when the CVE is only listed in a round-up', () => {
    const cves = ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4'];
    const r = scoreStory([it_({ cves, focalCves: focalCves(cves, []) })], lookup([cve('CVE-2026-1', { kev: kev(2) })]), NOW);
    expect(r.priority).toBe(2);
  });

  it('P1 for a ransomware-linked KEV entry due within 14 days', () => {
    const r = scoreStory([it_({ cves: ['CVE-2025-9'] })], lookup([cve('CVE-2025-9', { kev: kev(40, true, 5), published: iso(60) })]), NOW);
    expect(r.priority).toBe(1);
    expect(r.reasons.map((x) => x.code)).toContain('kev-ransom');
  });

  it('P1 for SSVC Exploitation=active on a recent CVE, P2 within a year, nothing when old', () => {
    const active = { ssvc: { exploitation: 'active' } };
    expect(scoreStory([it_({ cves: ['CVE-2026-1'] })], lookup([cve('CVE-2026-1', { ...active, published: iso(5) })]), NOW).priority).toBe(1);
    expect(scoreStory([it_({ cves: ['CVE-2026-1'] })], lookup([cve('CVE-2026-1', { ...active, published: iso(200) })]), NOW).priority).toBe(2);
    expect(scoreStory([it_({ cves: ['CVE-2021-1'] })], lookup([cve('CVE-2021-1', { ...active, published: iso(1800) })]), NOW).priority).toBe(4);
  });

  it('P1 when a tier-A advisory says exploited; P2 when only news says so', () => {
    expect(scoreStory([it_({ tier: 'A', exploited: true })], lookup([]), NOW).priority).toBe(1);
    expect(scoreStory([it_({ tier: 'C', exploited: true })], lookup([]), NOW).priority).toBe(2);
  });

  it('P2 for EPSS ≥ 0.088 with CVSS ≥ 7 on a recent CVE, but not for old CVEs', () => {
    const hot = cve('CVE-2026-7', { epss: 0.153, epssPct: 0.92, cvss: 9.8 });
    const r = scoreStory([it_({ cves: ['CVE-2026-7'] })], lookup([hot]), NOW);
    expect(r.priority).toBe(2);
    expect(r.reasons[0]!.label).toBe('EPSS 15% (92nd)');
    const log4shell = cve('CVE-2021-44228', { epss: 0.97, epssPct: 0.999, cvss: 10, published: iso(1800) });
    expect(scoreStory([it_({ cves: ['CVE-2021-44228'] })], lookup([log4shell]), NOW).priority).toBe(4);
  });

  it('old KEV entries only reach P3', () => {
    const r = scoreStory([it_({ cves: ['CVE-2021-44228'] })], lookup([cve('CVE-2021-44228', { kev: kev(1500), published: iso(1800) })]), NOW);
    expect(r.priority).toBe(3);
    expect(r.reasons[0]!.label).toBe('KEV (2022)');
  });

  it('P2 for an EPSS jump of 10+ points', () => {
    const r = scoreStory([it_({ cves: ['CVE-2026-8'] })], lookup([cve('CVE-2026-8', { epss: 0.3, epssPct: 0.97, epssDelta: 0.22 })]), NOW);
    expect(r.priority).toBe(2);
    expect(r.reasons.some((x) => x.code === 'epss-jump')).toBe(true);
  });

  it('P2 for a new public PoC on a high-severity CVE', () => {
    const c = cve('CVE-2026-9', { cvss: 8.1, poc: { count: 2, firstSeen: new Date(NOW - 10 * 3_600_000).toISOString() } });
    expect(scoreStory([it_({ cves: ['CVE-2026-9'] })], lookup([c]), NOW).priority).toBe(2);
  });

  it('P2 when 3+ independent sources cover it within 24h', () => {
    const items = ['a', 'b', 'c'].map((f, i) => it_({ feedId: f, time: NOW - DAY + i * 3_600_000 }));
    const r = scoreStory(items, lookup([]), NOW);
    expect(r.priority).toBe(2);
    expect(r.reasons[0]!.label).toBe('3 sources in 24h');
  });

  it('P3 for advisories and for research naming a CVE or threat; firehose advisories stay P4', () => {
    expect(scoreStory([it_({ tier: 'A' })], lookup([]), NOW).priority).toBe(3);
    expect(scoreStory([it_({ tier: 'B', hasThreatEntity: true })], lookup([]), NOW).priority).toBe(3);
    expect(scoreStory([it_({ tier: 'A', firehose: true, cves: ['CVE-2026-5'] })], lookup([]), NOW).priority).toBe(4);
    expect(scoreStory([it_({ tier: 'C' })], lookup([]), NOW).priority).toBe(4);
  });
});

describe('epssLabel', () => {
  it('formats probability and percentile', () => {
    expect(epssLabel(0.153, 0.921)).toBe('EPSS 15% (92nd)');
    expect(epssLabel(0.0123, 0.811)).toBe('EPSS 1.2% (81st)');
  });
});
