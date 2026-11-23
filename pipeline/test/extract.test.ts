import { describe, expect, it } from 'vitest';
import { claimsExploited, EntityMatcher, extractCves } from '../src/extract';

describe('extractCves', () => {
  it('finds and normalises CVE IDs, including odd hyphens and case', () => {
    expect(extractCves('Fixes cve-2026-1234, CVE‑2026‑123456 and CVE-2026-1234 again')).toEqual(['CVE-2026-1234', 'CVE-2026-123456']);
  });

  it('ignores implausible years and short sequence numbers', () => {
    expect(extractCves('CVE-1988-1234 CVE-2026-12 CVE-2999-1234')).toEqual([]);
  });
});

describe('claimsExploited', () => {
  it('detects exploitation claims', () => {
    expect(claimsExploited('Fortinet warns the flaw is actively exploited in attacks')).toBe(true);
    expect(claimsExploited('Microsoft is aware of limited, targeted exploitation of this issue')).toBe(true);
  });

  it('ignores negated mentions', () => {
    expect(claimsExploited('The Cisco PSIRT is not aware of any malicious use. No exploitation has been observed.')).toBe(false);
    expect(claimsExploited('There is no evidence that it is being exploited')).toBe(false);
  });
});

describe('EntityMatcher', () => {
  const matcher = new EntityMatcher({
    actors: [
      { name: 'APT28', aliases: ['Fancy Bear', 'Sofacy'] },
      { name: 'Careto', aliases: ['The Mask', 'Mask'] },
    ],
    malware: [
      { name: 'Play', aliases: ['PlayCrypt'] },
      { name: 'Emotet', aliases: ['Geodo'] },
      { name: 'Defender', aliases: [] },
      { name: 'LockBit', aliases: ['LockBit 3.0'] },
    ],
    vendors: [
      { name: 'Microsoft', aliases: ['Windows', 'Exchange Server'] },
      { name: 'Fortinet', aliases: ['FortiOS'] },
      { name: 'Progress Software', aliases: ['MOVEit', 'Progress'] },
    ],
  });

  it('maps multi-word aliases to the canonical name', () => {
    expect(matcher.match('New Fancy Bear campaign targets embassies').actors).toEqual(['APT28']);
  });

  it('matches all-common-word aliases ("Fancy Bear", "The Mask") only with exact casing', () => {
    expect(matcher.match('a fancy bear costume').actors).toEqual([]);
    expect(matcher.match('they wore the mask').actors).toEqual([]);
  });

  it('maps product aliases to vendors', () => {
    expect(matcher.match('FortiOS and Exchange Server patches released').vendors.sort()).toEqual(['Fortinet', 'Microsoft']);
  });

  it('requires a context word for common-word names', () => {
    expect(matcher.match('How to Play it safe this holiday').malware).toEqual([]);
    expect(matcher.match('Play ransomware hits retailer').malware).toEqual(['Play']);
  });

  it('requires context for plain capitalised words that are not well-known families', () => {
    expect(matcher.match('Microsoft Defender gets new features').malware).toEqual([]);
    expect(matcher.match('Emotet returns after hiatus').malware).toEqual(['Emotet']);
  });

  it('keeps distinctive mixed-case names without context', () => {
    expect(matcher.match('LockBit 3.0 affiliate arrested').malware).toEqual(['LockBit']);
  });

  it('skips ambiguous single-word vendor aliases', () => {
    expect(matcher.match('Progress on the investigation').vendors).toEqual([]);
    expect(matcher.match('MOVEit flaw exploited').vendors).toEqual(['Progress Software']);
  });
});
