import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { CveInfo } from '../../shared/types';
import { indexEt, indexNuclei, indexSigmaRule, indexYara } from '../src/detections';
import { catalogName, classifySighting } from '../src/enrich/circl';
import { diffSnapshots } from '../src/enrich/epss';
import { trackRansomwareFlips, type KevCatalog } from '../src/enrich/kev';
import { summarizeNvd } from '../src/enrich/nvd';
import { scoreStory, type ScoreItem } from '../src/score';
import { StateStore } from '../src/state';

describe('detection index parsers', () => {
  it('indexes Nuclei NDJSON', () => {
    const idx = {};
    const n = indexNuclei('{"ID":"CVE-2024-1234","Info":{"Name":"x"},"file_path":"http/cves/2024/CVE-2024-1234.yaml"}\nnot json\n', idx);
    expect(n).toBe(1);
    expect(idx).toEqual({ 'CVE-2024-1234': { nuclei: 'http/cves/2024/CVE-2024-1234.yaml', sigma: [], et: [], yara: [] } });
  });

  it('indexes ET Open rules by reference:cve (enabled and disabled)', () => {
    const idx: Record<string, { et: { sid: number }[] }> = {};
    indexEt(
      [
        'alert http any any -> any any (msg:"ET EXPLOIT Foo RCE (CVE-2024-1234)"; reference:cve,2024-1234; sid:2050001; rev:1;)',
        '#alert tcp any any -> any any (msg:"ET OLD"; reference:cve,CVE-2009-0696; reference:cve,2024-1234; sid:2009701; rev:2;)',
        'alert tcp any any -> any any (msg:"no cve"; sid:1;)',
      ].join('\n'),
      idx as never,
    );
    expect(idx['CVE-2024-1234']!.et.map((e) => e.sid)).toEqual([2050001, 2009701]);
    expect(idx['CVE-2009-0696']!.et).toHaveLength(1);
  });

  it('indexes Sigma rules from tags, titles and paths', () => {
    const idx: Record<string, { sigma: { title: string }[] }> = {};
    indexSigmaRule('rules/web/x.yml', 'title: Potential ToolShell Exploitation\ntags:\n    - attack.t1190\n    - cve.2025-53770\n', idx as never);
    indexSigmaRule('rules-emerging-threats/2021/Exploits/CVE-2021-44228/y.yml', 'title: Log4Shell\n', idx as never);
    expect(idx['CVE-2025-53770']!.sigma[0]!.title).toBe('Potential ToolShell Exploitation');
    expect(idx['CVE-2021-44228']).toBeDefined();
  });

  it('indexes YARA rules mentioning CVEs', () => {
    const idx: Record<string, { yara: string[] }> = {};
    indexYara('rule EXPL_CVE_2023_4966_Citrix {\n meta: description = "x"\n condition: true }\nrule Other { condition: false }\n', idx as never);
    expect(idx['CVE-2023-4966']!.yara).toEqual(['EXPL_CVE_2023_4966_Citrix']);
  });
});

describe('CIRCL helpers', () => {
  it('names catalogues', () => {
    expect(catalogName('cisa-kev')).toBe('CISA');
    expect(catalogName('enisa-cnw-kev')).toBe('ENISA');
    expect(catalogName('SiberKapan')).toBe('SiberKapan');
  });

  it('classifies sightings and flags honeypot exploitation', () => {
    expect(classifySighting({ vulnerability: 'cve-2026-1234', type: 'exploited', source: 'The Shadowserver (honeypot/exploited-vulns)', creation_timestamp: '2026-11-22T10:00:00Z' })).toEqual({
      cve: 'CVE-2026-1234',
      day: '2026-11-22',
      idx: 0,
      honeypot: true,
    });
    expect(classifySighting({ vulnerability: 'CVE-2026-1234', type: 'published-proof-of-concept', source: 'https://t.me/x', creation_timestamp: '2026-11-22T10:00:00Z' })?.idx).toBe(2);
    expect(classifySighting({ vulnerability: 'GHSA-xxxx', type: 'exploited', creation_timestamp: '2026-11-22T10:00:00Z' })).toBeNull();
  });
});

describe('NVD summary', () => {
  it('counts CPE matches and picks the primary CVSS', () => {
    expect(
      summarizeNvd({
        vulnStatus: 'Analyzed',
        configurations: [{ nodes: [{ cpeMatch: [{}, {}] }, { cpeMatch: [{}] }] }],
        metrics: { cvssMetricV31: [{ type: 'Secondary', cvssData: { baseScore: 5 } }, { type: 'Primary', cvssData: { baseScore: 9.8 } }] },
      }),
    ).toMatchObject({ status: 'Analyzed', cpes: 3, cvss: 9.8 });
  });
});

describe('EPSS model-change guard', () => {
  const snap = (model: string, date: string, epss: number) => ({ model, date, scores: new Map([['CVE-1', { epss, pct: 0.99 }]]) });
  it('pauses movers when the model version changes', () => {
    expect(diffSnapshots(snap('v2025', '2026-06-14', 0.1), snap('v2026.06.15', '2026-06-15', 0.6))).toEqual({
      movers: [],
      prev: {},
      modelChange: { from: 'v2025', to: 'v2026.06.15', date: '2026-06-15' },
    });
  });
  it('computes movers when the model is unchanged', () => {
    const d = diffSnapshots(snap('v5', '2026-11-22', 0.1), snap('v5', '2026-11-23', 0.6));
    expect(d.modelChange).toBeNull();
    expect(d.movers[0]).toMatchObject({ cve: 'CVE-1', kind: 'jump' });
  });
});

describe('KEV ransomware flips', () => {
  const cat = (entries: [string, string][]): KevCatalog => ({
    catalogVersion: 'x',
    dateReleased: '',
    count: entries.length,
    vulnerabilities: entries.map(([cveID, k]) => ({ cveID, knownRansomwareCampaignUse: k, vendorProject: '', product: '', vulnerabilityName: '', dateAdded: '', shortDescription: '', requiredAction: '', dueDate: '' })),
  });
  it('records Unknown→Known flips on existing entries, not new additions', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cd-kev-'));
    const store = new StateStore(dir);
    const now = Date.parse('2026-11-23T00:00:00Z');
    expect(trackRansomwareFlips(store, cat([['CVE-1', 'Unknown'], ['CVE-2', 'Known']]), now).size).toBe(0);
    const flips = trackRansomwareFlips(store, cat([['CVE-1', 'Known'], ['CVE-2', 'Known'], ['CVE-3', 'Known']]), now);
    expect([...flips.entries()]).toEqual([['CVE-1', '2026-11-23']]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('new scoring rules', () => {
  const NOW = Date.parse('2026-11-23T12:00:00Z');
  const item = (cves: string[]): ScoreItem => ({ feedId: 'f', tier: 'C', firehose: false, time: NOW, exploited: false, cves, focalCves: cves, hasThreatEntity: false });
  const cve = (extra: Partial<CveInfo>): CveInfo => ({ id: 'CVE-2026-1', epss: null, epssPct: null, epssDelta: null, stories: [], sources: 0, firstSeen: '', lastSeen: '', published: '2026-11-01', ...extra });
  const score = (c: CveInfo) => scoreStory([item([c.id])], () => c, NOW);

  it('ransomware-linked: P2 when in KEV, P3 otherwise', () => {
    const groups = [{ name: 'Qilin', role: 'operator' as const }, { name: 'Akira', role: 'operator' as const }];
    const kev = { dateAdded: '2025-01-01', dueDate: '2025-01-21', ransomware: true, name: 'x', requiredAction: 'patch' };
    expect(score(cve({ ransomware: { kevKnown: true, groups }, kev })).reasons.find((r) => r.code === 'ransomware-linked')?.label).toBe('Ransomware: Qilin, Akira');
    expect(score(cve({ ransomware: { kevKnown: false, groups } })).priority).toBe(3);
  });

  it('exploited-multi: a non-CISA catalogue listing raises to P2; Previdian alone is P3', () => {
    const ex = { notInCisa: true, exploited30d: 0, poc30d: 0, honeypot7d: false };
    expect(score(cve({ exploitation: { ...ex, catalogs: ['ENISA', 'Shadowserver'] } }))).toMatchObject({ priority: 2, reasons: [{ code: 'exploited-multi', label: 'Exploited: ENISA + Shadowserver' }] });
    expect(score(cve({ exploitation: { ...ex, catalogs: ['Previdian'] } })).priority).toBe(3);
  });

  it('honeypot hits and KEV ransomware flips are P2', () => {
    expect(score(cve({ exploitation: { catalogs: [], notInCisa: false, exploited30d: 4, poc30d: 0, honeypot7d: true } })).priority).toBe(2);
    expect(score(cve({ ransomware: { kevKnown: true, flippedAt: '2026-11-20', groups: [] } })).reasons.map((r) => r.code)).toContain('kev-ransom-flip');
  });
});
