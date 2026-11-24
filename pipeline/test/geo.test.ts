import { describe, expect, it } from 'vitest';
import { countryCode, countryName, countryNumeric, extractCountries } from '../src/geo';
import { cyberwatchCountry } from '../src/ransomware/activity';

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

  // Real sentences from the production audit (Nov 2026).
  it('ignores place names and idioms that contain a country word', () => {
    expect(extractCountries('the Office of the Information and Privacy Commissioner of British Columbia issued a news release')).toEqual([]);
    expect(extractCountries('Hospitals in New Mexico and New England hit; Latin American banks warned')).toEqual([]);
    expect(extractCountries('China Chopper web shell dropped on Exchange servers')).toEqual([]);
  });

  it('ignores language mentions', () => {
    expect(extractCountries('OpenAI and Cisco launch Shirudo (meaning "shield" in Japanese), an open-source Linux runtime')).toEqual([]);
    expect(extractCountries('The ransom note was written in Russian.')).toEqual([]);
    expect(extractCountries('Japanese companies targeted')).toEqual(['JP']);
  });

  it('ignores agency names that only attribute the source', () => {
    expect(extractCountries('Cisco RCE flaw exploited. The US Cybersecurity and Infrastructure Security Agency added it to KEV')).toEqual([]);
    expect(extractCountries('The Centre for Cybersecurity Belgium (CCB) warns that the flaws could let attackers')).toEqual([]);
    expect(extractCountries('The United States Cybersecurity and Infrastructure Security Agency added the flaw to its catalog')).toEqual([]);
    expect(extractCountries('Call center operator gets 8 years for scamming US residents')).toEqual(['US']);
  });

  it('drops a country word cut off by summary truncation', () => {
    expect(extractCountries('Critical vulnerability impacting Oracle Java. The Canadian…')).toEqual([]);
  });

  it('keeps genuine mentions', () => {
    expect(extractCountries('Norway says hackers exploited Microsoft security flaw to attack energy firms')).toEqual(['NO']);
    expect(extractCountries('A 43-year-old Kazakh national charged with taking part in a ransomware scheme was extradited from Italy').sort()).toEqual(['IT', 'KZ']);
    expect(extractCountries('South Korea’s power giant KEPCO confirms data breach')).toEqual(['KR']);
  });
});

describe('Cyberwatch country codes', () => {
  it('accepts ISO alpha-3/alpha-2 and IOC-style codes, rejects junk', () => {
    expect(cyberwatchCountry('USA')).toBe('US');
    expect(cyberwatchCountry('deu')).toBe('DE');
    expect(cyberwatchCountry('SLO')).toBe('SI');
    expect(cyberwatchCountry('FR')).toBe('FR');
    expect(cyberwatchCountry('')).toBeNull();
    expect(cyberwatchCountry('XYZ')).toBeNull();
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
