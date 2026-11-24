import { describe, expect, it } from 'vitest';
import type { ActorProfile, CveInfo, Story } from '../../shared/types';
import { matchStory, parseQuery, QUERY_HELP, resolveCountry, type MatchContext } from '../../web/src/lib/query';

const NOW = Date.parse('2026-11-24T12:00:00Z');
const HOUR = 3_600_000;

function story(over: Partial<Story> = {}): Story {
  return {
    id: 's1',
    title: 'Fortinet FortiOS zero-day exploited by Volt Typhoon',
    url: 'https://x/1',
    summary: 'Remote code execution in FortiOS SSL VPN.',
    feedId: 'cisa-alerts',
    feed: 'CISA Alerts',
    tier: 'A',
    group: 'gov',
    date: '2026-11-20T08:00:00Z',
    leadDate: '2026-11-20T08:00:00Z',
    firstSeen: '2026-11-20T08:00:00Z',
    lastSeen: new Date(NOW - 2 * HOUR).toISOString(),
    priority: 1,
    reasons: [{ code: 'kev-new', label: 'KEV +2d', cve: 'CVE-2026-1234' }],
    sources: [{ feedId: 'therecord', feed: 'The Record', tier: 'C', title: 'Chinese hackers hit Fortinet', url: 'https://y/1', date: '2026-11-21T00:00:00Z' }],
    sourceCount: 2,
    cves: ['CVE-2026-1234'],
    vendors: ['Fortinet'],
    actors: ['Volt Typhoon'],
    malware: ['LockBit'],
    countries: ['UA', 'US'],
    exploited: true,
    ...over,
  };
}

const actor: ActorProfile = {
  name: 'Volt Typhoon',
  aliases: ['Vanguard Panda', 'BRONZE SILHOUETTE'],
  country: 'CN',
  countryName: 'China',
  targets: [{ iso: 'DE', name: 'Germany', numeric: '276' }],
} as unknown as ActorProfile;

const cve: CveInfo = {
  id: 'CVE-2026-1234',
  epss: 0.5,
  epssPct: 0.99,
  epssDelta: null,
  kev: { dateAdded: '2026-11-22', dueDate: '2026-12-13', ransomware: true, name: 'x', requiredAction: 'patch' },
  ransomware: { kevKnown: true, groups: [{ name: 'Qilin', role: 'operator' }] },
  exploitation: { catalogs: ['CISA', 'ENISA'], notInCisa: false, exploited30d: 3, poc30d: 0, honeypot7d: false },
  detectionGap: true,
  stories: ['s1'],
  sources: 2,
  firstSeen: '',
  lastSeen: '',
};

const names = new Map([['ukraine', 'UA'], ['germany', 'DE'], ['china', 'CN']]);
const ctx: MatchContext = {
  now: NOW,
  cveInfo: new Map([[cve.id, cve]]),
  actors: new Map([[actor.name, actor]]),
  isWatched: () => true,
  isStarred: () => false,
  isNew: () => true,
  countryIso: (v) => names.get(v) ?? null,
};
const m = (q: string, s: Story = story()) => matchStory(s, parseQuery(q), ctx);

describe('search: every documented example works', () => {
  it.each(QUERY_HELP.map(([ex]) => ex).filter((ex) => !ex.startsWith('is:')))('%s parses to a filter (not free text)', (ex) => {
    const q = parseQuery(ex);
    expect(q.text).toEqual([]);
  });

  const positives: [string, boolean][] = [
    ['vendor:fortinet', true],
    ['actor:"volt typhoon"', true],
    ['malware:lockbit', true],
    ['cve:CVE-2026-1234', true],
    ['cve:2026-12', true],
    ['kev:yes', true],
    ['kev:no', false],
    ['exploited:yes', true],
    ['p:1,2', true],
    ['p:3', false],
    ['tier:A', true],
    ['tier:C', false],
    ['since:24h', true],
    ['since:1h', false],
    ['feed:cisa', true],
    ['feed:"the record"', true],
    ['country:UA', true],
    ['origin:CN', true],
    ['target:DE', true],
    ['date:2026-11-20', true],
    ['date:2026-11-21', false],
    ['ransomware:yes', true],
    ['ransomware:qilin', true],
    ['rw:akira', false],
    ['exploited-by:enisa', true],
    ['exploited-by:vulncheck', false],
    ['gap:yes', true],
    ['gap:no', false],
    ['is:watched', true],
    ['is:starred', false],
    ['is:new', true],
    ['"remote code"', true],
    ['chinese', true],
  ];
  it.each(positives)('%s → %s', (q, want) => expect(m(q)).toBe(want));
});

describe('search: fixes', () => {
  it('ransomware: is its own filter, not a malware family called "yes"', () => {
    expect(parseQuery('ransomware:yes')).toMatchObject({ ransomware: ['yes'], malware: [] });
    expect(m('ransomware:yes', story({ cves: [] }))).toBe(false);
  });

  it('actor: resolves MISP aliases', () => {
    expect(m('actor:"vanguard panda"')).toBe(true);
    expect(m('actor:"bronze silhouette"')).toBe(true);
    expect(m('actor:apt28')).toBe(false);
  });

  it('country/origin/target accept names and common synonyms', () => {
    expect(m('country:ukraine')).toBe(true);
    expect(m('country:usa')).toBe(true);
    expect(m('country:uk')).toBe(false);
    expect(m('country:uk', story({ countries: ['GB'] }))).toBe(true);
    expect(m('origin:china')).toBe(true);
    expect(m('target:germany')).toBe(true);
    expect(resolveCountry('UA', ctx)).toBe('UA');
    expect(resolveCountry('united kingdom', { countryIso: () => 'GB' })).toBe('GB');
  });

  it('combines filters with AND', () => {
    expect(m('vendor:fortinet kev:yes since:7d p:1')).toBe(true);
    expect(m('vendor:fortinet vendor:ivanti')).toBe(false);
  });
});
