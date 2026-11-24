// Outbound links for detection content and CVE pivots (plain navigations: no CSP impact).
export const nucleiUrl = (path: string) => `https://github.com/projectdiscovery/nuclei-templates/blob/main/${path}`;
export const sigmaUrl = (path: string) => `https://github.com/SigmaHQ/sigma/blob/master/${path}`;
export const circlUrl = (cve: string) => `https://vulnerability.circl.lu/vuln/${encodeURIComponent(cve.toLowerCase())}`;
export const euvdUrl = (id: string) => `https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(id)}`;
export const ghsaUrl = (id: string) => `https://github.com/advisories/${encodeURIComponent(id)}`;
export const osvUrl = (id: string) => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
export const rvmUrl = 'https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix';
export const rtmUrl = 'https://github.com/BushidoUK/Ransomware-Tool-Matrix';

export const ROLE_LABEL = { operator: '', affiliate: 'affiliate', broker: 'access broker', state: 'state-linked' } as const;
