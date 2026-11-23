// Builds the entity dictionary (actors, malware, vendors) from MISP galaxy clusters
// (which include the MITRE ATT&CK groups/software) plus CISA KEV vendor names.
// Rebuilt at most weekly; the result lives in the state branch.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CONFIG } from './config';
import { DICT_VERSION, type DictEntry, type EntityDict } from './extract';
import { fetchJson } from './fetch';
import { countryCode } from './geo';
import { clamp, toPlainText } from './text';
import { DAY } from './util';

interface GalaxyValue {
  value?: string;
  description?: string;
  meta?: {
    synonyms?: string[];
    country?: string;
    'cfr-suspected-state-sponsor'?: string;
    'cfr-suspected-victims'?: string[];
    'cfr-target-category'?: string[];
    'cfr-type-of-incident'?: string | string[];
    'targeted-sector'?: string[];
  };
}

interface GalaxyCluster {
  values?: GalaxyValue[];
}

function toEntry(v: GalaxyValue): DictEntry {
  const m = v.meta ?? {};
  const country = (m.country && countryCode(m.country)) || (m['cfr-suspected-state-sponsor'] && countryCode(m['cfr-suspected-state-sponsor'])) || undefined;
  const targets = [...new Set((m['cfr-suspected-victims'] ?? []).map(countryCode).filter((c): c is string => Boolean(c)))];
  const sectors = [...new Set([...(m['cfr-target-category'] ?? []), ...(m['targeted-sector'] ?? [])])].slice(0, 12);
  const incident = m['cfr-type-of-incident'];
  const desc = v.description ? toPlainText(v.description) : '';
  return {
    name: cleanName(v.value!),
    aliases: (m.synonyms ?? []).map(cleanName),
    ...(country ? { country } : {}),
    ...(targets.length ? { targets } : {}),
    ...(sectors.length ? { sectors } : {}),
    ...(incident ? { motive: Array.isArray(incident) ? incident.join(', ') : incident } : {}),
    ...(desc ? { description: clamp(desc, 700) } : {}),
  };
}

/** Product → vendor aliases so "FortiOS" or "NetScaler" tag the vendor. Extend as needed. */
export const VENDOR_ALIASES: Record<string, string[]> = {
  Microsoft: ['Windows', 'Exchange Server', 'SharePoint', 'Outlook', 'Microsoft 365', 'Azure', 'Entra ID', 'Hyper-V', 'MSHTML', 'Win32k', 'NTLM', 'Office'],
  Google: ['Chrome', 'Chromium', 'Android', 'Pixel'],
  Apple: ['iOS', 'iPadOS', 'macOS', 'Safari', 'WebKit', 'visionOS', 'watchOS'],
  Cisco: ['IOS XE', 'IOS XR', 'Cisco ASA', 'Firepower', 'Webex', 'Meraki', 'ISE'],
  Fortinet: ['FortiOS', 'FortiGate', 'FortiWeb', 'FortiManager', 'FortiClient', 'FortiSIEM', 'FortiProxy', 'FortiAnalyzer', 'FortiSwitch', 'FortiVoice', 'FortiMail'],
  'Palo Alto Networks': ['PAN-OS', 'GlobalProtect', 'Palo Alto', 'Prisma Access', 'Cortex XDR', 'Expedition'],
  Ivanti: ['Connect Secure', 'Policy Secure', 'EPMM', 'MobileIron', 'Pulse Secure', 'Neurons for ZTA', 'Endpoint Manager'],
  Citrix: ['NetScaler', 'Citrix ADC', 'Citrix Gateway', 'XenServer', 'ShareFile'],
  VMware: ['ESXi', 'vCenter', 'vSphere', 'Workstation', 'Aria Operations', 'Tanzu', 'VMware Tools'],
  Atlassian: ['Confluence', 'Jira', 'Bitbucket', 'Bamboo'],
  Oracle: ['WebLogic', 'E-Business Suite', 'PeopleSoft', 'MySQL', 'VirtualBox'],
  SonicWall: ['SonicOS', 'SMA 100', 'SMA1000'],
  'Progress Software': ['MOVEit', 'Telerik', 'WS_FTP', 'WhatsUp Gold', 'Kemp LoadMaster', 'Progress Software'],
  Juniper: ['Junos', 'Junos OS', 'SRX'],
  F5: ['BIG-IP', 'BIG-IQ', 'NGINX'],
  Veeam: ['Backup & Replication'],
  SAP: ['NetWeaver', 'S/4HANA'],
  Adobe: ['ColdFusion', 'Acrobat', 'Magento', 'Experience Manager'],
  Apache: ['Tomcat', 'Struts', 'Log4j', 'ActiveMQ', 'OFBiz', 'Airflow', 'HugeGraph'],
  Linux: ['Linux kernel'],
  Mozilla: ['Firefox', 'Thunderbird'],
  CrushFTP: ['CrushFTP'],
  Zimbra: ['Zimbra Collaboration'],
  'Check Point': ['Quantum Security Gateway', 'Check Point'],
  GitLab: ['GitLab'],
  Kubernetes: ['Kubernetes', 'ingress-nginx'],
  OpenSSH: ['OpenSSH'],
  OpenSSL: ['OpenSSL'],
  Commvault: ['Commvault'],
  SolarWinds: ['SolarWinds', 'Serv-U', 'Web Help Desk'],
  ConnectWise: ['ScreenConnect', 'ConnectWise'],
  Zyxel: ['Zyxel'],
  'D-Link': ['D-Link'],
  'TP-Link': ['TP-Link'],
  QNAP: ['QNAP', 'QTS'],
  Synology: ['Synology', 'DiskStation'],
  Samsung: ['Samsung', 'Exynos'],
  Qualcomm: ['Qualcomm', 'Snapdragon'],
  Salesforce: ['Salesforce'],
  Okta: ['Okta'],
  Cloudflare: ['Cloudflare'],
  AWS: ['AWS', 'Amazon Web Services'],
  WordPress: ['WordPress'],
  Docker: ['Docker'],
  Jenkins: ['Jenkins'],
  'Trend Micro': ['Apex One'],
  Sophos: ['Sophos'],
  SonarSource: ['SonarQube'],
};

const VENDOR_SKIP = new Set(['multiple vendors', 'multiple', 'unknown', 'n/a', 'various']);

function cleanName(v: string): string {
  // "APT28 - G0007" → "APT28"; "RedAlert Ransomware" → "RedAlert" (so variants merge).
  return v
    .replace(/\s+-\s+[GS]\d{4}$/, '')
    .replace(/\s+ransomware$/i, '')
    .trim();
}

async function fetchGalaxy(file: string): Promise<DictEntry[]> {
  let lastError = 'no source tried';
  for (const base of CONFIG.urls.mispGalaxy) {
    const { result, json } = await fetchJson<GalaxyCluster>(`${base}/${file}`, { timeoutMs: 60_000, maxBytes: 64 * 1024 * 1024 });
    if (json?.values) return json.values.filter((v) => v.value).map(toEntry);
    lastError = result.error ?? `HTTP ${result.httpStatus}`;
  }
  throw new Error(`${file}: ${lastError}`);
}

/** Merge entries whose names/aliases overlap so each real-world entity has one canonical name. */
function mergeEntries(lists: DictEntry[][]): DictEntry[] {
  const byAlias = new Map<string, DictEntry>();
  const out: DictEntry[] = [];
  for (const list of lists) {
    for (const e of list) {
      const keys = [e.name, ...e.aliases].map((a) => a.toLowerCase());
      const existing = keys.map((k) => byAlias.get(k)).find(Boolean);
      const target: DictEntry = existing ?? { name: e.name, aliases: [] };
      if (!existing) out.push(target);
      // Fill attribution/profile fields from whichever source has them.
      target.country ??= e.country;
      target.targets ??= e.targets;
      target.sectors ??= e.sectors;
      target.motive ??= e.motive;
      target.description ??= e.description;
      for (const a of [e.name, ...e.aliases]) {
        const k = a.toLowerCase();
        if (!byAlias.has(k)) {
          byAlias.set(k, target);
          if (a !== target.name) target.aliases.push(a);
        }
      }
    }
  }
  return out;
}

export async function buildDicts(stateDir: string = CONFIG.paths.state): Promise<EntityDict> {
  const [threatActors, mitreGroups, ransomware, mitreMalware, malpedia] = await Promise.all([
    fetchGalaxy('threat-actor.json'),
    fetchGalaxy('mitre-intrusion-set.json'),
    fetchGalaxy('ransomware.json'),
    fetchGalaxy('mitre-malware.json'),
    fetchGalaxy('malpedia.json').catch(() => [] as DictEntry[]),
  ]);

  const vendorNames = new Set<string>(Object.keys(VENDOR_ALIASES));
  const kevPath = join(stateDir, 'kev.json');
  if (existsSync(kevPath)) {
    const kev = JSON.parse(readFileSync(kevPath, 'utf8')) as { vulnerabilities?: { vendorProject?: string }[] };
    for (const v of kev.vulnerabilities ?? []) {
      const name = v.vendorProject?.trim();
      if (name && !VENDOR_SKIP.has(name.toLowerCase())) vendorNames.add(name);
    }
  }
  const vendors: DictEntry[] = [...vendorNames].sort().map((name) => ({ name, aliases: VENDOR_ALIASES[name] ?? [] }));

  const dict: EntityDict = {
    version: DICT_VERSION,
    builtAt: new Date().toISOString(),
    sources: ['MISP galaxy: threat-actor, mitre-intrusion-set, ransomware, mitre-malware, malpedia', 'CISA KEV vendorProject', 'CyberDigest product aliases'],
    actors: mergeEntries([threatActors, mitreGroups]),
    // Only actor profiles use descriptions; dropping them for ~6k malware entries keeps the file small.
    malware: mergeEntries([ransomware, mitreMalware, malpedia]).map(({ name, aliases }) => ({ name, aliases })),
    vendors,
    ransomware: mergeEntries([ransomware]).map(({ name, aliases, description }) => ({ name, aliases, ...(description ? { description } : {}) })),
  };
  const path = join(stateDir, 'dicts', 'entities.json');
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(dict));
  return dict;
}

/** Load the cached dictionary, rebuilding it when missing or older than the max age. */
export async function loadOrBuildDicts(stateDir: string = CONFIG.paths.state): Promise<{ dict: EntityDict | null; rebuilt: boolean; error?: string }> {
  const path = join(stateDir, 'dicts', 'entities.json');
  if (existsSync(path)) {
    const cached = JSON.parse(readFileSync(path, 'utf8')) as EntityDict;
    const age = Date.now() - Date.parse(cached.builtAt);
    if (cached.version === DICT_VERSION && age < CONFIG.enrich.dictMaxAgeDays * DAY) return { dict: cached, rebuilt: false };
    try {
      return { dict: await buildDicts(stateDir), rebuilt: true };
    } catch (e) {
      return { dict: cached, rebuilt: false, error: String(e) };
    }
  }
  try {
    return { dict: await buildDicts(stateDir), rebuilt: true };
  } catch (e) {
    return { dict: null, rebuilt: false, error: String(e) };
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const d = await buildDicts();
  console.log(`dictionary: ${d.actors.length} actors, ${d.malware.length} malware, ${d.vendors.length} vendors`);
}
