import { describe, expect, it } from 'vitest';
import { countryCode, countryName, countryNumeric, extractCountries } from '../src/geo';

describe('extractCountries', () => {
  it('finds names, short forms and demonyms', () => {
    expect(extractCountries('Russian hackers target Ukraine and U.S. agencies').sort()).toEqual(['RU', 'UA', 'US']);
    expect(extractCountries('North Korean IT workers infiltrate UK firms').sort()).toEqual(['GB', 'KP']);
  });

  it('prefers the longest match (South Korea is not Korea)', () => {
    expect(extractCountries('Attacks on South Korea rise')).toEqual(['KR']);
  });

  it('skips ambiguous names and lowercase words', () => {
    expect(extractCountries('Georgia hospital breach; Jordan said; chinese food; turkey dinner')).toEqual([]);
  });

  it('ignores group names that look like countries', () => {
    expect(extractCountries('Cuba ransomware hits retailer')).toEqual([]);
    expect(extractCountries('Sanctions on Cuba')).toEqual(['CU']);
  });

  it('does not match "US" inside compound tokens', () => {
    expect(extractCountries('US-CERT advisory')).toEqual([]);
  });
});

describe('country helpers', () => {
  it('maps MISP victim names to ISO codes, ignoring organisations', () => {
    expect(countryCode('Russian Federation')).toBe('RU');
    expect(countryCode('United States')).toBe('US');
    expect(countryCode('Korea, Republic of')).toBe('KR');
    expect(countryCode('NATO')).toBeNull();
  });

  it('provides short display names and numeric ids for the map', () => {
    expect(countryName('RU')).toBe('Russia');
    expect(countryName('FR')).toBe('France');
    expect(countryNumeric('RU')).toBe('643');
  });
});
