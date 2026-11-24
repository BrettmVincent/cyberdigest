// Registry of every upstream source: licence, required credit, what CyberDigest does with it,
// and its status this run. Published as sources.json (credits page + health panel).
import type { SourceInfo } from '../../shared/types';

type Static = Omit<SourceInfo, 'status' | 'detail' | 'retrievedAt' | 'version'>;

export const SOURCE_DEFS: Static[] = [
  { id: 'feeds', name: 'Curated RSS/Atom feeds', url: 'config/feeds.yaml', license: "Each publisher's terms", credit: 'Headlines and short summaries link to every original article.', changes: 'HTML stripped, summaries shortened, duplicates clustered', use: 'data' },
  { id: 'cisa-kev', name: 'CISA Known Exploited Vulnerabilities Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', license: 'U.S. Government work', credit: 'CISA Known Exploited Vulnerabilities Catalog', changes: 'Joined to CVEs; ransomware-flag changes tracked', use: 'data' },
  { id: 'epss', name: 'FIRST EPSS', url: 'https://www.first.org/epss/', license: 'Free to use (FIRST)', credit: 'EPSS by FIRST', changes: 'Daily scores joined to CVEs; day-over-day movers computed', use: 'data' },
  { id: 'cvelist', name: 'CVE Program cvelistV5 (incl. CISA-ADP Vulnrichment)', url: 'https://github.com/CVEProject/cvelistV5', license: 'CVE Program Terms of Use', credit: 'CVE® records from the CVE Program; SSVC from CISA Vulnrichment', changes: 'CVSS, CWE and SSVC extracted', use: 'data' },
  { id: 'poc', name: 'nomi-sec PoC-in-GitHub', url: 'https://github.com/nomi-sec/PoC-in-GitHub', license: 'CC0', credit: 'PoC-in-GitHub by nomi-sec', changes: 'Counted only; repositories are not linked (many contain malware)', use: 'aggregate' },
  { id: 'misp-galaxy', name: 'MISP galaxy (incl. MITRE ATT&CK clusters)', url: 'https://github.com/MISP/misp-galaxy', license: 'CC0 / BSD-2-Clause', credit: 'MISP galaxy clusters; MITRE ATT&CK®', changes: 'Names, aliases, attribution and descriptions used for entity tagging and profiles', use: 'data' },
  { id: 'rvm', name: 'Ransomware Vulnerability Matrix', url: 'https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix', license: 'CC BY 4.0', credit: 'Ransomware Vulnerability Matrix by Will Thomas (BushidoUK), CC BY 4.0', changes: 'Markdown tables parsed; group names normalised and joined to CVEs', use: 'data' },
  { id: 'rtm', name: 'Ransomware Tool Matrix', url: 'https://github.com/BushidoUK/Ransomware-Tool-Matrix', license: 'CC BY 4.0', credit: 'Ransomware Tool Matrix by Will Thomas (BushidoUK), CC BY 4.0', changes: 'Markdown tables parsed; group names normalised', use: 'data' },
  { id: 'circl-kev', name: 'CIRCL Vulnerability-Lookup: KEV catalogues', url: 'https://vulnerability.circl.lu/', license: 'Per catalogue (CISA, ENISA, Shadowserver, Previdian, SiberKapan, CIRCL); CIRCL open data CC BY 4.0', credit: 'Source: CIRCL Vulnerability-Lookup (catalogue owners named per CVE)', changes: 'Catalogue membership per CVE', use: 'data' },
  { id: 'circl-sightings', name: 'CIRCL Vulnerability-Lookup: sightings', url: 'https://vulnerability.circl.lu/', license: 'CIRCL open data (CC BY 4.0, unconfirmed for third-party posts)', credit: 'Source: CIRCL Vulnerability-Lookup', changes: 'Counted per CVE and type over 30 days; post text never stored', use: 'aggregate' },
  { id: 'rulezet', name: 'CIRCL Rulezet', url: 'https://rulezet.org/', license: 'Per rule', credit: 'Rule counts via CIRCL Rulezet', changes: 'Rule counts for hot CVEs only', use: 'aggregate' },
  { id: 'nvd', name: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/', license: 'Public domain', credit: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.', changes: 'Analysis status, CPE count and CVSS fallback', use: 'data' },
  { id: 'euvd', name: 'ENISA European Vulnerability Database (EUVD)', url: 'https://euvd.enisa.europa.eu/', license: 'ENISA: reproduction authorised provided the source is acknowledged', credit: 'Source: ENISA European Vulnerability Database (EUVD)', changes: 'EUVD identifiers joined to CVEs (daily mapping dump) and linked', use: 'data' },
  { id: 'ghsa', name: 'GitHub Advisory Database', url: 'https://github.com/advisories', license: 'CC BY 4.0', credit: 'GitHub Advisory Database, CC BY 4.0', changes: 'Reviewed advisories: GHSA ID, affected packages and first patched version for tracked CVEs', use: 'data' },
  { id: 'osv', name: 'OSV.dev (Open Source Vulnerabilities)', url: 'https://osv.dev/', license: 'CC BY 4.0 (per-source licences apply)', credit: 'OSV.dev, CC BY 4.0', changes: 'Record existence, GHSA aliases and related-advisory counts for tracked CVEs; linked', use: 'data' },
  { id: 'vulncheck-kev', name: 'VulnCheck KEV (Community)', url: 'https://vulncheck.com/kev', license: 'VulnCheck Community terms; prominent attribution required', credit: 'VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)', changes: 'Catalogue membership per CVE, shown as "VulnCheck KEV" alongside CIRCL catalogues', use: 'data' },
  { id: 'nuclei', name: 'ProjectDiscovery nuclei-templates', url: 'https://github.com/projectdiscovery/nuclei-templates', license: 'MIT', credit: 'nuclei-templates by ProjectDiscovery', changes: 'Indexed by CVE; linked, not re-hosted', use: 'link' },
  { id: 'et-open', name: 'Proofpoint Emerging Threats Open', url: 'https://rules.emergingthreats.net/', license: 'BSD (ET SIDs) / GPLv2', credit: 'ET Open rules by Proofpoint', changes: 'Indexed by CVE reference (SID and message only)', use: 'link' },
  { id: 'sigma', name: 'SigmaHQ rules', url: 'https://github.com/SigmaHQ/sigma', license: 'Detection Rule License 1.1', credit: 'Sigma rules by SigmaHQ contributors (DRL 1.1)', changes: 'Indexed by CVE tag/path; titles and links only', use: 'link' },
  { id: 'yara-forge', name: 'YARA Forge', url: 'https://github.com/YARAHQ/yara-forge', license: 'Per rule set (GPL-3.0 packaging)', credit: 'YARA Forge (YARAHQ)', changes: 'Rule names indexed by CVE mention', use: 'link' },
  { id: 'ransomlook', name: 'RansomLook', url: 'https://www.ransomlook.io/', license: 'CC BY 4.0', credit: 'Source: RansomLook.io (CC BY 4.0), aggregated by CyberDigest', changes: 'Leak-site posts counted per group and week; victim names discarded', use: 'aggregate' },
  { id: 'ransomware-live', name: 'Ransomware.live (PRO API)', url: 'https://www.ransomware.live/', license: 'Non-commercial use with attribution; no raw data republishing', credit: 'Source: Ransomware.live', changes: 'Victims counted per group, sector, country and week; no victim data published', use: 'aggregate' },
  { id: 'cyberwatch', name: 'Cyberwatch (Valéry Rieß-Marchive, LeMagIT)', url: 'https://github.com/Casualtek/Cyberwatch', license: 'CC BY-NC 4.0', credit: 'Cyberwatch by Valéry Rieß-Marchive, CC BY-NC 4.0, aggregated by CyberDigest', changes: 'Publicly reported cyberattacks counted per country; victim names discarded', use: 'aggregate' },
  { id: 'ransomchats', name: 'Ransomchats (Valéry Rieß-Marchive)', url: 'https://github.com/Casualtek/Ransomchats', license: 'MIT', credit: 'Ransomchats by Valéry Rieß-Marchive', changes: 'Negotiation chats counted per group; text not reproduced', use: 'aggregate' },
  { id: 'threatlabz-notes', name: 'Zscaler ThreatLabz ransomware_notes', url: 'https://github.com/ThreatLabz/ransomware_notes', license: 'MIT', credit: 'Ransom note archive: Zscaler ThreatLabz', changes: 'Note files counted per family; notes not reproduced', use: 'aggregate' },
  { id: 'ransomwhere', name: 'Ransomwhere (Jack Cable)', url: 'https://ransomwhe.re/', license: 'CC BY 4.0 (DOI 10.5281/zenodo.6512122)', credit: 'Ransomwhere, CC BY 4.0, doi:10.5281/zenodo.6512122', changes: 'Payments summed per family; addresses not published', use: 'aggregate' },
  { id: 'crocodyli', name: 'crocodyli ThreatActors-TTPs', url: 'https://github.com/crocodyli/ThreatActors-TTPs', license: 'No licence (link only)', credit: 'ATT&CK mapping: crocodyli/ThreatActors-TTPs', changes: 'Linked only', use: 'link' },
  { id: 'hudsonrock', name: 'Hudson Rock / Infostealers.com', url: 'https://www.infostealers.com/', license: 'Feed: publisher terms; tools: link only', credit: 'Infostealer research by Hudson Rock (RSS + links)', changes: 'RSS headlines; free lookup tools linked', use: 'link' },
  { id: 'natural-earth', name: 'Natural Earth via world-atlas', url: 'https://github.com/topojson/world-atlas', license: 'Public domain / ISC', credit: 'Map data: Natural Earth', changes: 'Bundled country outlines', use: 'data' },
];

export class SourceRegistry {
  private entries = new Map<string, SourceInfo>();

  constructor(previous: SourceInfo[] = []) {
    const prev = new Map(previous.map((p) => [p.id, p]));
    for (const d of SOURCE_DEFS) {
      const p = prev.get(d.id);
      this.entries.set(d.id, { ...d, status: d.use === 'link' ? 'ok' : 'skipped', detail: d.use === 'link' ? 'Linked only' : 'Not run yet', retrievedAt: p?.retrievedAt ?? null, version: p?.version ?? null });
    }
  }

  set(id: string, patch: Partial<Pick<SourceInfo, 'status' | 'detail' | 'version'>> & { retrieved?: boolean }): void {
    const e = this.entries.get(id);
    if (!e) throw new Error(`unknown source id ${id}`);
    if (patch.status) e.status = patch.status;
    if (patch.detail !== undefined) e.detail = patch.detail;
    if (patch.version !== undefined) e.version = patch.version;
    if (patch.retrieved) e.retrievedAt = new Date().toISOString();
  }

  get(id: string): SourceInfo | undefined {
    return this.entries.get(id);
  }

  all(): SourceInfo[] {
    return [...this.entries.values()];
  }
}
