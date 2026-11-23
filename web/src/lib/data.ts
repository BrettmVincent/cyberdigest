import type { ActorProfile, CveInfo, EpssMovers, Health, KevEntry, Meta, Overview, RansomwareData, SourceInfo, Story, Trends } from '../../../shared/types';

export interface Dataset {
  meta: Meta;
  stories: Story[];
  cves: CveInfo[];
  kev: KevEntry[];
  epss: EpssMovers;
  trends: Trends;
  health: Health;
  overview: Overview;
  actors: ActorProfile[];
  ransomware: RansomwareData;
  sources: SourceInfo[];
}

async function getJson<T>(name: string, version?: string): Promise<T> {
  // GitHub Pages caches for 10 minutes; a version query string busts it when the data changes.
  const url = `data/${name}${version ? `?v=${encodeURIComponent(version)}` : ''}`;
  const res = await fetch(url, { cache: version ? 'default' : 'no-store' });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return (await res.json()) as T;
}

export function fetchMeta(): Promise<Meta> {
  return getJson<Meta>('meta.json');
}

export async function loadDataset(meta?: Meta): Promise<Dataset> {
  const m = meta ?? (await fetchMeta());
  const v = m.generatedAt;
  const [stories, cves, kev, epss, trends, health, overview, actors, ransomware, sources] = await Promise.all([
    getJson<Story[]>('stories.json', v),
    getJson<CveInfo[]>('cves.json', v),
    getJson<KevEntry[]>('kev.json', v),
    getJson<EpssMovers>('epss.json', v),
    getJson<Trends>('trends.json', v),
    getJson<Health>('health.json', v),
    getJson<Overview>('overview.json', v),
    getJson<ActorProfile[]>('actors.json', v),
    getJson<RansomwareData>('ransomware.json', v),
    getJson<SourceInfo[]>('sources.json', v),
  ]);
  return { meta: m, stories, cves, kev, epss, trends, health, overview, actors, ransomware, sources };
}
