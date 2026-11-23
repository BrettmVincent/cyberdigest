// Rule-based entity extraction: CVE IDs, vendors, threat actors, malware, exploitation claims.

export interface DictEntry {
  name: string;
  aliases: string[];
  /** Actor attribution (MISP galaxy), ISO alpha-2. */
  country?: string;
  /** Suspected victim countries, ISO alpha-2. */
  targets?: string[];
  sectors?: string[];
  motive?: string;
  description?: string;
}

/** Bump when the dictionary format changes, to force a rebuild of cached dictionaries. */
export const DICT_VERSION = 3;

export interface EntityDict {
  version?: number;
  builtAt: string;
  sources: string[];
  actors: DictEntry[];
  malware: DictEntry[];
  vendors: DictEntry[];
  /** MISP ransomware cluster (with descriptions), used for ransomware group profiles and alias resolution. */
  ransomware?: DictEntry[];
}

export interface Entities {
  cves: string[];
  vendors: string[];
  actors: string[];
  malware: string[];
}

type Kind = 'actors' | 'malware' | 'vendors';

const HYPHENS = /[‐-―−﹘﹣－]/g;
const CVE_RE = /\bCVE[-_ ](\d{4})[-_ ](\d{4,7})\b/gi;

export function extractCves(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.replace(HYPHENS, '-').matchAll(CVE_RE)) {
    const year = Number(m[1]);
    if (year >= 1999 && year <= new Date().getUTCFullYear() + 1) out.add(`CVE-${m[1]}-${m[2]}`);
  }
  return [...out];
}

const EXPLOITED_RE =
  /\b(exploited in the wild|actively exploited|active(ly)? exploit(ation|ed)|under active (attack|exploitation)|in-the-wild exploitation|exploitation (has been |was )?(observed|detected|reported)|is aware (of|that) .{0,60}?exploit\w*|being exploited|known exploited vulnerabilit\w*|zero-day .{0,30}?exploited|exploited zero-day|exploited as a zero-day|mass exploitation)/i;

const NEGATION_RE = /\b(no|not|never|without|unaware|nor)\b[^.;]*$/i;

/**
 * True when the text claims in-the-wild exploitation, ignoring negated mentions
 * ("is not aware of any exploitation", "no exploitation has been observed").
 * Callers pass the headline plus the opening of the body, not the whole article.
 */
export function claimsExploited(text: string): boolean {
  const re = new RegExp(EXPLOITED_RE.source, 'gi');
  for (const m of text.matchAll(re)) {
    const before = text.slice(Math.max(0, m.index - 60), m.index);
    if (!NEGATION_RE.test(before)) return true;
  }
  return false;
}

/** Words that collide with entity aliases. Single-token aliases in this set only match when followed by a context word. */
export const COMMON_WORDS = new Set(
  (
    'about above access account action active actor admin agent alert alpha android angel anubis apple apex arm army ' +
    'atlas atom aurora avalanche azure babylon backdoor badger banker baron base bear beacon bee beta big bison black ' +
    'blackout blade blaze blind blizzard blue bolt bot botnet bounty box bread bright brain bridge buffalo bug butter ' +
    'cactus calypso camel canary captain carbon castle cat chaos charming checkmate cherry chrome cicada circle citrine ' +
    'clipper cloud clover cobalt code comet copper core cosmic crab crane crimson crow crypto crystal cuba cyber dark ' +
    'dart data dawn delta demon desert diamond dino dog dragon dream dropper duke dust eagle earth echo eclipse elephant ' +
    'emerald empire energy evil exploit falcon fancy fire firefly flame flash fog forest fox frog frost fury galaxy ' +
    'game gamma gang garden gate gemini generic ghost giant glacier gold golden gorilla grace graphite gray green grey ' +
    'griffin guard hacker hades hammer hawk heart helix hermes hero hive hook horizon hornet hunter ice inferno iron ' +
    'island ivory jaguar jupiter karma kernel key king kitten knight lazy legion leopard light lightning lion loader ' +
    'lock locker lotus lucky luna lynx magic magnet mamba manta mars maze medusa mercury mesh meteor microsoft midnight ' +
    'mint mirage mist monkey monster moon mosaic mustang mystic neptune nexus night ninja noble nomad north nova oasis ' +
    'ocean office omega onyx orange orbit orca origin outlaw owl panda panther paper patch pegasus phantom phoenix ' +
    'pioneer pirate pixel planet play plug pluto poison polar prime prism progress proxy pulse puma python quantum ' +
    'rabbit radar rage rain ransom ransomware rat raven razor rebel red redline reign remote rhino ring river robin ' +
    'rocket rogue rook rose royal ruby rust saber sage salt sandstorm saturn scanner scarlet scorpion sea serpent ' +
    'shade shadow shark shell sidewinder signal silence silent silver sky slate smoke snake snow solar sonic space ' +
    'spark spectre sphinx spider spirit spy squid star stealer steel storm strike sun swift sword tank target team ' +
    'tempest thor thunder tiger titan torch tornado trident trojan tropic turtle twilight typhoon unknown venom venus ' +
    'viper void volcano vortex wallet warlock wasp water web whale white widow wind winter wizard wolf worm yellow ' +
    'zero zeus zombie windows linux office outlook teams exchange github google cloud update patch malware phishing ' +
    'wiper spyware adware rootkit webshell miner implant payload tunnel stealth hunter monday tuesday wednesday thursday ' +
    'friday saturday sunday january february march april may june july august september october november december'
  ).split(/\s+/),
);

/** Plain-word names distinctive enough to match without a context word. Extend as needed. */
const WELL_KNOWN = new Set(
  (
    'emotet qakbot trickbot dridex ursnif gozi zloader danabot icedid lumma vidar rhadamanthys pikabot latrodectus ' +
    'mimikatz mirai gafgyt mozi remcos formbook njrat gootloader smokeloader amadey stealc glupteba matanbuchus ' +
    'lazarus kimsuky turla sandworm gamaredon andariel hafnium nobelium sednit sofacy fin7 ' +
    'akira qilin conti ryuk clop babuk phobos mallox trigona rhysida sodinokibi egregor lockergoga hellcat ' +
    'interlock kinsing shamoon industroyer triton stuxnet evilginx kimwolf aisuru strela'
  ).split(/\s+/),
);

/** Single-word vendor names/aliases too ambiguous to tag on their own. */
const VENDOR_STOP = new Set(['progress', 'arm', 'office', 'teams', 'exchange', 'workstation', 'pixel', 'expedition', 'docker', 'unknown', 'multiple', 'ise', 'srx']);

/** A capitalised common-word alias ("Play", "Royal") only counts when followed by one of these. */
const CONTEXT_WORDS = new Set([
  'ransomware', 'malware', 'botnet', 'stealer', 'infostealer', 'loader', 'rat', 'backdoor', 'gang', 'group',
  'operators', 'operator', 'affiliate', 'affiliates', 'actor', 'actors', 'apt', 'trojan', 'wiper', 'variant',
  'campaign', 'crew', 'hackers', 'extortion', 'spyware', 'worm', 'dropper', 'implant',
]);

const TOKEN_RE = /[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/g;

function tokenize(s: string): string[] {
  return s.replace(HYPHENS, '-').replace(/[’']s\b/g, '').match(TOKEN_RE) ?? [];
}

interface Target {
  kind: Kind;
  name: string;
  /** Exact-case token sequence required (proper-noun aliases). */
  cs?: string;
  /** Must be followed by a context word. */
  ctx?: boolean;
}

const MAX_N = 6;

export class EntityMatcher {
  private map = new Map<string, Target[]>();

  constructor(dict: Pick<EntityDict, Kind>) {
    // Registration order sets precedence when one alias maps to several kinds.
    for (const kind of ['actors', 'malware', 'vendors'] as const) {
      for (const entry of dict[kind]) {
        for (const alias of uniqStrings([entry.name, ...entry.aliases])) this.add(kind, entry.name, alias);
      }
    }
  }

  private add(kind: Kind, name: string, alias: string): void {
    const tokens = tokenize(alias);
    if (tokens.length === 0 || tokens.length > MAX_N) return;
    const key = tokens.join(' ').toLowerCase();
    let target: Target;
    if (tokens.length === 1) {
      const t = tokens[0]!;
      const hasDigit = /\d/.test(t);
      const lower = t.toLowerCase();
      if (/^\d+$/.test(t)) return;
      if (t === lower && !hasDigit) return; // all-lowercase single word: too generic
      const isAcronym = t === t.toUpperCase();
      const minLen = hasDigit ? 3 : kind === 'vendors' && isAcronym ? 2 : 4;
      if (t.length < minLen) return;
      if (kind === 'vendors') {
        if (VENDOR_STOP.has(lower)) return;
        target = { kind, name, cs: t };
      } else {
        // A plain capitalised word ("Defender", "First", "Done") reads as ordinary English in
        // title-case headlines, so it needs a context word unless it is a well-known family/actor.
        const plainWord = /^[A-Z][a-z]+$/.test(t);
        const needsContext = COMMON_WORDS.has(lower) || (plainWord && !WELL_KNOWN.has(lower));
        target = needsContext ? { kind, name, cs: t, ctx: true } : { kind, name, cs: t };
      }
    } else {
      // Aliases made of plain words ("The Mask", "Fancy Bear") must match with their capitalisation;
      // ones with digits or internal capitals ("LockBit 3.0", "APT 28") are distinctive in any case.
      const plainWords = tokens.every((t) => /^[A-Z]?[a-z]+$/.test(t));
      target = plainWords ? { kind, name, cs: tokens.join(' ') } : { kind, name };
    }
    const list = this.map.get(key);
    if (!list) this.map.set(key, [target]);
    else if (!list.some((x) => x.kind === kind && x.name === name)) list.push(target);
  }

  match(text: string): Omit<Entities, 'cves'> {
    const out = { actors: new Set<string>(), malware: new Set<string>(), vendors: new Set<string>() };
    const tokens = tokenize(text);
    const lower = tokens.map((t) => t.toLowerCase());
    for (let i = 0; i < tokens.length; i++) {
      for (let n = Math.min(MAX_N, tokens.length - i); n >= 1; n--) {
        const targets = this.map.get(lower.slice(i, i + n).join(' '));
        if (!targets) continue;
        const exact = tokens.slice(i, i + n).join(' ');
        const near = [lower[i - 1], lower[i + n]];
        const hasContext = near.some((w) => w !== undefined && CONTEXT_WORDS.has(w));
        // First matching target wins: actors take precedence over malware over vendors.
        const hit = targets.find((t) => (!t.cs || t.cs === exact) && (!t.ctx || hasContext));
        if (!hit) continue;
        out[hit.kind].add(hit.name);
        i += n - 1;
        break;
      }
    }
    return { actors: [...out.actors], malware: [...out.malware], vendors: [...out.vendors] };
  }
}

function uniqStrings(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.trim()).filter(Boolean))];
}

export function extractEntities(matcher: EntityMatcher | null, title: string, body: string): Entities {
  const text = `${title}. ${body}`;
  const ents = matcher ? matcher.match(text) : { actors: [], malware: [], vendors: [] };
  return { cves: extractCves(text), ...ents };
}
