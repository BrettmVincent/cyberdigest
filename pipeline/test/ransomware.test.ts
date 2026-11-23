import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildRansomware, sumWindow, weekly, weekStarts } from '../src/ransomware/activity';
import { GroupResolver, groupKey, parseRoleMarkers } from '../src/ransomware/aliases';
import { parseRtm, parseRvm } from '../src/ransomware/matrices';
import { SourceRegistry } from '../src/sources';
import { StateStore } from '../src/state';

const RVM_MD = `## Network Edge Devices
- VPNs, Firewalls

### \`Pulse Secure / Ivanti\`
| Product | CVE(s) | Ransomware Group(s) | Source(s) |
|---|---|---|---|
| Ivanti Connect Secure | CVE-2024-21887 | Pioneer Kitten+, DragonForce | [cisa.gov](https://www.cisa.gov/aa24-241a) / [trendmicro.com](https://www.trendmicro.com/x) |
| Ivanti Connect Secure | CVE-2023-46805, CVE-2024-21887 | Scattered Spider*, *Br0k3r | [a.com](https://a.com/1) |

### \`Fortinet\`
| Product | CVE(s) | Ransomware Group(s) | Source(s) |
|---|---|---|---|
| FortiOS | CVE-2018-13379 | Akira | [b.com](https://b.com) |
`;

const RTM_MD = `## Exfiltration Tools
> [!TIP]
> text

| Tool Name | Threat Group Usage |
|---|---|
| File[.]io | Mallox, Babuk |
| Rclone | Akira, Scattered Spider* |
`;

describe('Will Thomas matrices', () => {
  it('parses RVM rows with vendor headings, multi-CVE cells, role markers and source links', () => {
    const rows = parseRvm(RVM_MD, 'NetworkEdge');
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({
      cves: ['CVE-2024-21887'],
      product: 'Ivanti Connect Secure',
      vendor: 'Pulse Secure / Ivanti',
      groups: [
        { name: 'Pioneer Kitten', role: 'state' },
        { name: 'DragonForce', role: 'operator' },
      ],
      sources: ['https://www.cisa.gov/aa24-241a', 'https://www.trendmicro.com/x'],
    });
    expect(rows[1]!.cves).toEqual(['CVE-2023-46805', 'CVE-2024-21887']);
    expect(rows[1]!.groups).toEqual([
      { name: 'Scattered Spider', role: 'affiliate' },
      { name: 'Br0k3r', role: 'broker' },
    ]);
    expect(rows[2]!.vendor).toBe('Fortinet');
  });

  it('fails loudly when the table format changes', () => {
    expect(() => parseRvm('### Vendor\n| Name | Thing |\n|---|---|\n| a | b |', 'X')).toThrow(/no "CVE/);
    expect(() => parseRtm('| A | B |\n|---|---|\n| x | y |', 'X')).toThrow();
  });

  it('parses RTM tool tables and un-defangs tool names', () => {
    expect(parseRtm(RTM_MD, 'Exfiltration')).toEqual([
      { tool: 'File.io', category: 'Exfiltration', groups: [{ name: 'Mallox', role: 'operator' }, { name: 'Babuk', role: 'operator' }] },
      { tool: 'Rclone', category: 'Exfiltration', groups: [{ name: 'Akira', role: 'operator' }, { name: 'Scattered Spider', role: 'affiliate' }] },
    ]);
  });
});

describe('group name normalisation', () => {
  it('reads role markers', () => {
    expect(parseRoleMarkers('Pioneer Kitten+')).toEqual({ name: 'Pioneer Kitten', role: 'state' });
    expect(parseRoleMarkers('*Br0k3r')).toEqual({ name: 'Br0k3r', role: 'broker' });
    expect(parseRoleMarkers('Storm-0501*')).toEqual({ name: 'Storm-0501', role: 'affiliate' });
  });

  it('merges spellings across trackers into one canonical group', () => {
    const r = new GroupResolver([{ name: 'INC Ransom', aliases: ['incransom', 'inc'] }, { name: 'BlackCat (ALPHV)', aliases: ['alphv', 'blackcat'] }], [
      { name: 'BlackCat', aliases: ['Noberus'] },
    ]);
    expect(r.resolve('inc ransom')).toEqual(r.resolve('INC Ransom'));
    expect(r.resolve('incransom').name).toBe('INC Ransom');
    expect(r.resolve('alphv').name).toBe('BlackCat (ALPHV)');
    expect(r.resolve('Noberus').name).toBe('BlackCat (ALPHV)');
    expect(r.resolve('Some New Gang')).toEqual({ id: 'somenewgang', name: 'Some New Gang' });
    expect(groupKey('The Gentlemen')).toBe(groupKey('TheGentlemen'));
  });
});

describe('weekly counting', () => {
  it('buckets daily counts into Monday-aligned weeks', () => {
    const now = Date.parse('2026-11-23T12:00:00Z'); // a Monday
    const weeks = weekStarts(now, 3);
    expect(weeks).toEqual(['2026-11-09', '2026-11-16', '2026-11-23']);
    const days = { '2026-11-10': { a: 2 }, '2026-11-22': { a: 1, b: 4 }, '2026-11-23': { b: 1 }, '2026-10-01': { a: 9 } };
    const w = weekly(days, weeks);
    expect(w.byKey).toEqual({ a: [2, 1, 0], b: [0, 4, 1] });
    expect(w.total).toEqual([2, 5, 1]);
    expect(sumWindow(days, '2026-11-17', '2026-11-23')).toEqual({ a: 1, b: 5 });
  });
});

describe('no victim data is ever published', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cd-rw-'));
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.RANSOMWARE_LIVE_KEY;
  });

  it('reduces RansomLook posts and ransomware.live victims to counts', async () => {
    const victims = ['Acme Hospital Ltd', 'Contoso Nursery', 'Fabrikam Bank'];
    const today = new Date().toISOString();
    const [y, m] = today.split('-');
    vi.stubGlobal('fetch', async (url: string) => {
      const body = url.includes('ransomlook.io/api/posts')
        ? { posts: victims.map((v, i) => ({ group_name: i ? 'qilin' : 'inc ransom', post_title: v, discovered: today })) }
        : url.includes(`api-pro.ransomware.live/victims/?year=${y}&month=${m}`)
          ? victims.map((v) => ({ victim: v, post_title: v, group: 'akira', discovered: today, country: 'US', activity: 'Healthcare', domain: `${v}.example` }))
          : url.includes('api-pro.ransomware.live/victims')
            ? []
            : null;
      return body ? new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }) : new Response('nope', { status: 404 });
    });
    process.env.RANSOMWARE_LIVE_KEY = 'test-key';
    const store = new StateStore(join(dir, 'state'));
    const reg = new SourceRegistry();
    const out = await buildRansomware({
      u: { store, http: {}, gates: {}, now: Date.now() },
      reg,
      resolver: new GroupResolver([{ name: 'INC Ransom', aliases: ['inc ransom'] }]),
      rvm: { rows: [], updated: null },
      rtm: { rows: [], updated: null },
      mispRansomware: [],
      kevIndex: new Map(),
      flips: new Map(),
      cveInfo: () => undefined,
    });
    const json = JSON.stringify(out.data);
    for (const v of victims) expect(json).not.toContain(v);
    expect(json).not.toMatch(/post_title|"victim"|domain/);
    // ...and nothing victim-level was written to the (public) state branch either.
    const stateJson = JSON.stringify([store.readJson('ransomware/ransomlook.json', {}), store.readJson('ransomware/ransomware-live.json', {})]);
    for (const v of victims) expect(stateJson).not.toContain(v);
    // The counts survive.
    expect(out.data.totals.ransomlook?.last7).toBe(3);
    expect(out.data.groups.find((g) => g.name === 'INC Ransom')?.last7).toBe(1);
    expect(out.data.sectors).toEqual([{ name: 'Healthcare', count: 3 }]);
    expect(out.countries).toEqual({ US: 3 });
    rmSync(dir, { recursive: true, force: true });
  });
});
