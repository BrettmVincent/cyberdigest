import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { computeMovers, parseEpssCsv } from '../src/enrich/epss';

describe('EPSS', () => {
  it('parses the daily CSV including its metadata line', () => {
    const csv = '#model_version:v2026.06.15,score_date:2026-11-23T00:00:00+0000\ncve,epss,percentile\nCVE-2026-1,0.5,0.99\nCVE-2026-2,0.001,0.1\n';
    const r = parseEpssCsv(gzipSync(csv));
    expect(r.model).toBe('v2026.06.15');
    expect(r.date).toBe('2026-11-23');
    expect(r.scores.get('CVE-2026-1')).toEqual({ epss: 0.5, pct: 0.99 });
  });

  it('flags jumps and percentile crossings between snapshots', () => {
    const prev = new Map([
      ['CVE-1', { epss: 0.05, pct: 0.9 }],
      ['CVE-2', { epss: 0.2, pct: 0.96 }],
      ['CVE-3', { epss: 0.3, pct: 0.97 }],
    ]);
    const cur = new Map([
      ['CVE-1', { epss: 0.4, pct: 0.98 }], // jump +0.35
      ['CVE-2', { epss: 0.25, pct: 0.991 }], // crosses p99
      ['CVE-3', { epss: 0.3, pct: 0.97 }], // unchanged
    ]);
    const { movers } = computeMovers(prev, cur);
    expect(movers.map((m) => [m.cve, m.kind])).toEqual([
      ['CVE-1', 'jump'],
      ['CVE-2', 'cross-p99'],
    ]);
  });
});
