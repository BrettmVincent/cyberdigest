import { describe, expect, it } from 'vitest';
import { clusterItems, type ClusterInput } from '../src/cluster';
import { extractCves } from '../src/extract';
import { titleTokens } from '../src/text';

const H = 3_600_000;
const T0 = Date.parse('2026-11-20T00:00:00Z');

function item(feedId: string, title: string, hours: number, cves: string[] = [], entities: string[] = []): ClusterInput {
  return { feedId, time: T0 + hours * H, cves, titleCves: extractCves(title), entities: new Set(entities), tokens: titleTokens(title) };
}

const groupsOf = (items: ClusterInput[]) =>
  clusterItems(items)
    .map((g) => g.sort((a, b) => a - b))
    .sort((a, b) => a[0]! - b[0]!);

describe('clusterItems', () => {
  it('merges coverage of the same CVE across outlets', () => {
    const items = [
      item('cisco-psirt', 'Cisco ISE Remote Code Execution Vulnerability', 0, ['CVE-2026-20100']),
      item('bleepingcomputer', 'Cisco warns of critical ISE flaw exploited in attacks', 5, ['CVE-2026-20100']),
      item('securityweek', 'Cisco Patches Exploited ISE Vulnerability', 9, ['CVE-2026-20100']),
    ];
    expect(groupsOf(items)).toEqual([[0, 1, 2]]);
  });

  it('does not let a multi-CVE round-up bridge unrelated stories', () => {
    const items = [
      item('thehackernews', 'Ivanti EPMM flaw exploited', 0, ['CVE-2026-1001']),
      item('bleepingcomputer', 'Zimbra zero-day used in attacks', 1, ['CVE-2026-2002']),
      item('cisa-alerts', 'CISA Adds Four Known Exploited Vulnerabilities to Catalog', 2, ['CVE-2026-1001', 'CVE-2026-2002', 'CVE-2026-3003', 'CVE-2026-4004']),
    ];
    expect(groupsOf(items)).toEqual([[0], [1], [2]]);
  });

  it('links a round-up to stories through a CVE named in both headlines', () => {
    const items = [
      item('msrc', 'CVE-2026-5555 Windows SMB Elevation of Privilege Vulnerability', 0, ['CVE-2026-5555']),
      item('tenable', 'Patch Tuesday fixes 80 CVEs (CVE-2026-5555)', 3, ['CVE-2026-5555', 'CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4']),
    ];
    expect(groupsOf(items)).toEqual([[0, 1]]);
  });

  it('never merges templated titles from the same feed by wording alone', () => {
    const items = [
      item('cisa-alerts', 'CISA Adds One Known Exploited Vulnerability to Catalog', 0, ['CVE-2026-1111']),
      item('cisa-alerts', 'CISA Adds One Known Exploited Vulnerability to Catalog', 30, ['CVE-2026-2222']),
    ];
    expect(groupsOf(items)).toEqual([[0], [1]]);
  });

  it('merges near-identical headlines from different outlets, but not near-misses', () => {
    const items = [
      item('bleepingcomputer', 'Akira ransomware breaches SonicWall SSL VPN accounts', 0, [], ['akira', 'sonicwall']),
      item('therecord', 'Akira ransomware gang breaches SonicWall SSL VPN accounts', 4, [], ['akira', 'sonicwall']),
      item('securityweek', 'SonicWall releases firmware for SMA 100 appliances', 6, [], ['sonicwall']),
    ];
    expect(groupsOf(items)).toEqual([[0, 1], [2]]);
  });

  it('respects the time window for headline similarity', () => {
    const items = [
      item('bleepingcomputer', 'Akira ransomware breaches SonicWall SSL VPN accounts', 0),
      item('therecord', 'Akira ransomware breaches SonicWall SSL VPN accounts', 24 * 10),
    ];
    expect(groupsOf(items)).toEqual([[0], [1]]);
  });
});
