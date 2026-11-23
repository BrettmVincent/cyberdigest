// Country gazetteer: rule-based extraction of country mentions, MISP victim-name → ISO mapping,
// and display names. Country data: i18n-iso-countries (ISO 3166-1).
import { createRequire } from 'node:module';
import countries from 'i18n-iso-countries';

const require = createRequire(import.meta.url);
countries.registerLocale(require('i18n-iso-countries/langs/en.json'));

/** Short display names where the ISO English name is long or formal. */
const DISPLAY: Record<string, string> = {
  US: 'United States', GB: 'United Kingdom', RU: 'Russia', CN: 'China', HK: 'Hong Kong', MO: 'Macao', NL: 'Netherlands', AE: 'United Arab Emirates', IR: 'Iran', TW: 'Taiwan', KR: 'South Korea', KP: 'North Korea',
  SY: 'Syria', MD: 'Moldova', LA: 'Laos', VE: 'Venezuela', BO: 'Bolivia', TZ: 'Tanzania', CZ: 'Czechia', VN: 'Vietnam',
  CD: 'DR Congo', CG: 'Congo', MK: 'North Macedonia', PS: 'Palestine', BN: 'Brunei', FM: 'Micronesia', TR: 'Türkiye', CI: "Côte d'Ivoire",
};

/** Demonyms and common short forms (case-sensitive proper nouns). */
const EXTRA: Record<string, string[]> = {
  US: ['American', 'Americans'], GB: ['British', 'Britain', 'England', 'Scotland', 'Wales'], RU: ['Russian', 'Russians', 'Kremlin'],
  CN: ['Chinese', 'Beijing', 'PRC'], IR: ['Iranian', 'Iranians', 'Tehran'], KP: ['North Korean', 'North Koreans', 'DPRK', 'Pyongyang'],
  KR: ['South Korean', 'South Koreans', 'Seoul'], UA: ['Ukrainian', 'Ukrainians', 'Kyiv'], IL: ['Israeli', 'Israelis'], DE: ['German', 'Germans'],
  FR: ['French'], IT: ['Italian'], ES: ['Spanish'], JP: ['Japanese'], TW: ['Taiwanese'], IN: ['Indian'], PK: ['Pakistani'], VN: ['Vietnamese'],
  BR: ['Brazilian'], CA: ['Canadian'], AU: ['Australian'], NL: ['Dutch', 'Netherlands'], BE: ['Belgian'], PL: ['Polish'], CZ: ['Czech'],
  TR: ['Turkish'], SA: ['Saudi'], AE: ['Emirati', 'UAE'], MX: ['Mexican'], ID: ['Indonesian'], PH: ['Filipino', 'Philippine'],
  SG: ['Singaporean'], TH: ['Thai'], MY: ['Malaysian'], NG: ['Nigerian'], ZA: ['South African'], EG: ['Egyptian'], CH: ['Swiss'],
  SE: ['Swedish'], NO: ['Norwegian'], DK: ['Danish'], FI: ['Finnish'], IE: ['Irish'], AT: ['Austrian'], RO: ['Romanian'], HU: ['Hungarian'],
  GR: ['Greek'], PT: ['Portuguese'], BY: ['Belarusian', 'Belarus'], AM: ['Armenian'], AZ: ['Azerbaijani'], KZ: ['Kazakh'], LT: ['Lithuanian'],
  LV: ['Latvian'], EE: ['Estonian'], SK: ['Slovak'], SI: ['Slovenian'], HR: ['Croatian'], RS: ['Serbian'], BG: ['Bulgarian'],
  AR: ['Argentine', 'Argentinian'], CL: ['Chilean'], CO: ['Colombian'], PE: ['Peruvian'], VE: ['Venezuelan'], KE: ['Kenyan'],
  MA: ['Moroccan'], DZ: ['Algerian'], LB: ['Lebanese'], SY: ['Syrian', 'Syria'], IQ: ['Iraqi'], JO: ['Jordanian'], QA: ['Qatari'],
  KW: ['Kuwaiti'], BD: ['Bangladeshi'], LK: ['Sri Lankan'], AF: ['Afghan'], MN: ['Mongolian'], KH: ['Cambodian'], MD: ['Moldova', 'Moldovan'],
  LA: ['Laos'], TZ: ['Tanzania'], NZ: ['New Zealander'], GE: ['Georgian'],
};

/** Country names that are usually something else in security news. */
const AMBIGUOUS = new Set(['Georgia', 'Jordan', 'Chad', 'Guinea', 'Niger', 'Dominica', 'Turkey', 'Monaco', 'Mali', 'Togo', 'Jersey', 'Panama', 'Congo', 'Korea', 'Sudan', 'Comoros', 'Wales']);
/** If the next word is one of these, the "country" is a threat-group or malware name (e.g. "Cuba ransomware"). */
const NOT_A_COUNTRY_NEXT = new Set(['ransomware', 'gang', 'malware', 'stealer', 'rat', 'botnet', 'operator', 'operators']);

const TOKEN_RE = /[A-Za-zÀ-ɏ0-9](?:[A-Za-zÀ-ɏ0-9.'’-]*[A-Za-zÀ-ɏ0-9])?/g;
const tokenize = (s: string) => s.replace(/[’']s\b/g, '').match(TOKEN_RE) ?? [];

interface Entry {
  iso: string;
  exact: string;
}

const MAX_N = 5;
const gazetteer = new Map<string, Entry>();
const byName = new Map<string, string>();

function addName(iso: string, name: string, matchInText: boolean): void {
  byName.set(name.toLowerCase(), iso);
  if (!matchInText || AMBIGUOUS.has(name) || /,|\(/.test(name)) return;
  const tokens = tokenize(name);
  if (tokens.length === 0 || tokens.length > MAX_N) return;
  if (tokens.length === 1 && tokens[0]!.length < 4 && !['US', 'U.S', 'UK', 'UAE', 'PRC', 'DPRK', 'USA', 'U.S.A'].includes(tokens[0]!)) return;
  const key = tokens.join(' ').toLowerCase();
  if (!gazetteer.has(key)) gazetteer.set(key, { iso, exact: tokens.join(' ') });
}

for (const [iso, names] of Object.entries(countries.getNames('en', { select: 'all' }))) {
  for (const n of names) addName(iso, n, true);
}
for (const [iso, names] of Object.entries(EXTRA)) for (const n of names) addName(iso, n, true);
for (const [iso, n] of Object.entries(DISPLAY)) addName(iso, n, true);

/** ISO 3166-1 alpha-2 codes of countries mentioned in the text (case-sensitive proper nouns). */
export function extractCountries(text: string): string[] {
  const out = new Set<string>();
  const tokens = tokenize(text);
  const lower = tokens.map((t) => t.toLowerCase());
  for (let i = 0; i < tokens.length; i++) {
    for (let n = Math.min(MAX_N, tokens.length - i); n >= 1; n--) {
      const e = gazetteer.get(lower.slice(i, i + n).join(' '));
      if (!e || e.exact !== tokens.slice(i, i + n).join(' ')) continue;
      if (!NOT_A_COUNTRY_NEXT.has(lower[i + n] ?? '')) out.add(e.iso);
      i += n - 1;
      break;
    }
  }
  return [...out];
}

/** Map a country name (e.g. from MISP "cfr-suspected-victims") to ISO alpha-2; null for non-countries like "NATO". */
export function countryCode(name: string): string | null {
  const n = name.trim();
  if (/^[A-Z]{2}$/.test(n) && countries.isValid(n)) return n;
  return byName.get(n.toLowerCase()) ?? countries.getAlpha2Code(n, 'en') ?? null;
}

export function countryName(iso: string): string {
  return DISPLAY[iso] ?? countries.getName(iso, 'en')?.replace(/,.*$/, '') ?? iso;
}

/** ISO 3166-1 numeric code (as used by Natural Earth / world-atlas geometry ids). */
export function countryNumeric(iso: string): string | null {
  return countries.alpha2ToNumeric(iso) ?? null;
}
