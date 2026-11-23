<script lang="ts">
  import type { ActorProfile, Overview, RansomwareData } from '../../../shared/types';
  import { GROUP_LABELS } from '../../../shared/types';
  import { q } from '../lib/query';
  import ChartCard from './charts/ChartCard.svelte';
  import HBars from './charts/HBars.svelte';
  import StackedBars, { type Series } from './charts/StackedBars.svelte';
  import StatTile from './charts/StatTile.svelte';
  import WorldMap, { type MapMode } from './charts/WorldMap.svelte';
  import Sparkline from './Sparkline.svelte';

  interface Props {
    overview: Overview;
    actors: ActorProfile[];
    ransomware: RansomwareData;
    trendDays: string[];
    onFilter: (token: string) => void;
    onActor: (name: string) => void;
    onRansomware: () => void;
    onGroup: (id: string) => void;
  }
  let { overview, actors, ransomware, trendDays, onFilter, onActor, onRansomware, onGroup }: Props = $props();

  let mode = $state<MapMode>('news');
  const modes = $derived<{ id: MapMode; label: string; token: string; sub: string }[]>([
    { id: 'news', label: 'In the news', token: 'country', sub: 'Countries named in story headlines and summaries, last 14 days' },
    { id: 'origin', label: 'Actor origin', token: 'origin', sub: 'Suspected origin of threat actors mentioned in stories, last 14 days (MISP galaxy attribution)' },
    { id: 'targeted', label: 'Actor targets', token: 'target', sub: "Countries this fortnight's active actors are known to target: profile data, not confirmed incidents" },
    ...(ransomware.countrySource
      ? [
          {
            id: 'ransom' as const,
            label: ransomware.countrySource === 'ransomware.live' ? 'Ransomware claims' : 'Reported attacks',
            token: 'country',
            sub:
              ransomware.countrySource === 'ransomware.live'
                ? 'Ransomware leak-site claims by victim country, 30 days: unverified claims (Source: Ransomware.live)'
                : 'Publicly reported cyberattacks by country, 30 days (Cyberwatch by Valéry Rieß-Marchive, CC BY-NC 4.0)',
          },
        ]
      : []),
  ]);
  const current = $derived(modes.find((m) => m.id === mode)!);

  const ranked = $derived(
    [...overview.countries]
      .filter((c) => c[mode] > 0)
      .sort((a, b) => b[mode] - a[mode] || a.name.localeCompare(b.name))
      .slice(0, 12)
      .map((c) => ({
        key: c.iso,
        label: c.name,
        value: c[mode],
        title: mode === 'origin' ? c.originActors.join(', ') : mode === 'targeted' ? c.targetActors.join(', ') : undefined,
      })),
  );

  const shortDay = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });

  const prioritySeries = $derived<Series[]>([
    { key: 'p3', label: 'P3 Monitor', cls: 'f-p3', values: overview.priorityByDay.map((d) => d.p[2]) },
    { key: 'p2', label: 'P2 High', cls: 'f-p2', values: overview.priorityByDay.map((d) => d.p[1]) },
    { key: 'p1', label: 'P1 Act now', cls: 'f-p1', values: overview.priorityByDay.map((d) => d.p[0]) },
  ]);
  const kevSeries = $derived<Series[]>([
    { key: 'rw', label: 'Ransomware-linked', cls: 'f-s2', values: overview.kevByWeek.map((w) => w.ransomware) },
    { key: 'other', label: 'Other KEV additions', cls: 'f-s1', values: overview.kevByWeek.map((w) => w.total - w.ransomware) },
  ]);

  const activeActors = $derived(actors.filter((a) => a.total30 > 0).slice(0, 10));
  const t = $derived(overview.tiles);
</script>

<div class="scroll overview">
  <div class="tiles">
    <StatTile label="P1 stories (7d)" value={t.p1[0]} previous={t.p1[1]} hint="Act-now stories first reported in the last 7 days. Click to list them." onSelect={() => onFilter('p:1 since:7d')} />
    <StatTile label="New KEV entries (7d)" value={t.kev[0]} previous={t.kev[1]} hint="CVEs added to CISA's Known Exploited Vulnerabilities catalog" onSelect={() => onFilter('kev:yes since:7d')} />
    <StatTile label="Exploited CVEs in the news" value={t.exploitedCves[0]} previous={t.exploitedCves[1]} hint="Distinct KEV or SSVC-active CVEs mentioned in stories this week" onSelect={() => onFilter('exploited:yes since:7d')} />
    <StatTile label="P1–P3 stories (7d)" value={t.stories[0]} previous={t.stories[1]} hint="Stories worth an analyst's attention this week" onSelect={() => onFilter('p:1,2,3 since:7d')} />
  </div>

  <div class="row map-row">
    <ChartCard title="Global activity" subtitle={current.sub} class="map-card">
      {#snippet actions()}
        <div class="seg" role="radiogroup" aria-label="Map layer">
          {#each modes as m (m.id)}
            <button role="radio" aria-checked={mode === m.id} class:on={mode === m.id} onclick={() => (mode = m.id)}>{m.label}</button>
          {/each}
        </div>
      {/snippet}
      <WorldMap {mode} countries={overview.countries} onSelect={(iso) => onFilter(`${current.token}:${iso}`)} ariaLabel="World map, {current.label}. Top: {ranked.slice(0, 5).map((r) => `${r.label} ${r.value}`).join(', ') || 'none'}." />
    </ChartCard>
    <ChartCard title="Top countries" subtitle={current.label}>
      <HBars rows={ranked} labelWidth="wide" onSelect={(r) => onFilter(`${current.token}:${r.key}`)} empty="No countries for this layer yet." />
    </ChartCard>
  </div>

  <div class="row two">
    <ChartCard title="Stories by priority" subtitle="First reported per day, last 30 days (P4 context excluded)">
      {#snippet legend()}
        {#each [...prioritySeries].reverse() as s (s.key)}<span class="legend-key"><span class="legend-swatch {s.cls}"></span>{s.label}</span>{/each}
      {/snippet}
      {#snippet table()}
        <table class="data">
          <thead><tr><th>Day</th><th class="num">P1</th><th class="num">P2</th><th class="num">P3</th><th class="num">P4</th></tr></thead>
          <tbody>{#each [...overview.priorityByDay].reverse() as d (d.day)}<tr><td>{d.day}</td>{#each d.p as n, i (i)}<td class="num">{n}</td>{/each}</tr>{/each}</tbody>
        </table>
      {/snippet}
      <StackedBars
        labels={overview.priorityByDay.map((d) => d.day)}
        series={prioritySeries}
        formatLabel={shortDay}
        ariaLabel="Stacked bars of P1, P2 and P3 stories per day over 30 days"
        onSelect={(i) => onFilter(q('date', overview.priorityByDay[i]!.day))}
        selectHint="Click to list that day's stories"
      />
    </ChartCard>
    <ChartCard title="CISA KEV additions" subtitle="Per week, last 26 weeks">
      {#snippet legend()}
        {#each [...kevSeries].reverse() as s (s.key)}<span class="legend-key"><span class="legend-swatch {s.cls}"></span>{s.label}</span>{/each}
      {/snippet}
      {#snippet table()}
        <table class="data">
          <thead><tr><th>Week of</th><th class="num">Total</th><th class="num">Ransomware-linked</th></tr></thead>
          <tbody>{#each [...overview.kevByWeek].reverse() as w (w.week)}<tr><td>{w.week}</td><td class="num">{w.total}</td><td class="num">{w.ransomware}</td></tr>{/each}</tbody>
        </table>
      {/snippet}
      <StackedBars labels={overview.kevByWeek.map((w) => w.week)} series={kevSeries} tickEvery={4} formatLabel={shortDay} ariaLabel="Stacked bars of CISA KEV additions per week, split by ransomware use" />
    </ChartCard>
  </div>

  <div class="row three">
    <ChartCard title="Active threat actors" subtitle="Stories per day, 30 days · click for profile">
      {#if activeActors.length === 0}
        <p class="muted">No named actors in recent stories.</p>
      {:else}
        <ul class="actors">
          {#each activeActors as a (a.name)}
            <li>
              <button onclick={() => onActor(a.name)}>
                <span class="a-name">{a.name}</span>
                <span class="a-origin" title={a.countryName ? `Suspected origin: ${a.countryName}` : 'Origin unattributed'}>{a.country ?? '—'}</span>
                <Sparkline values={a.days} days={trendDays} baseline={null} label={a.name} width={84} height={20} />
                <span class="a-n num" title="Stories in the last 7 days">{a.last7}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </ChartCard>
    <ChartCard title="Ransomware this week" subtitle="Leak-site claims (unverified) · most active groups">
      {#snippet actions()}<button class="btn small" onclick={onRansomware}>Open</button>{/snippet}
      {#if ransomware.totals.ransomlook}
        {@const t = ransomware.totals.ransomlook}
        <p class="rw-sum"><b class="num">{t.last7}</b> posts by <b class="num">{t.groups7}</b> groups <span class="muted">(last week {t.prev7})</span></p>
      {/if}
      <ul class="actors">
        {#each ransomware.groups.filter((g) => g.last7 > 0).slice(0, 6) as g (g.id)}
          <li>
            <button onclick={() => onGroup(g.id)}>
              <span class="a-name">{g.name}</span>
              <span class="a-origin">{g.cves.length ? `${g.cves.length} CVE` : ''}</span>
              <Sparkline values={g.weekly} days={ransomware.weeks} baseline={null} label={g.name} width={84} height={20} />
              <span class="a-n num">{g.last7}</span>
            </button>
          </li>
        {/each}
      </ul>
      {#if ransomware.kevFlips.length}<p class="rw-sum"><b>{ransomware.kevFlips.length}</b> CVEs newly ransomware-linked by CISA</p>{/if}
    </ChartCard>
    <ChartCard title="Most-affected vendors" subtitle="P1–P3 stories, 14 days">
      <HBars rows={overview.vendors.map((v) => ({ key: v.name, label: v.name, value: v.stories, note: v.high ? `${v.high} high` : undefined }))} onSelect={(r) => onFilter(q('vendor', r.key))} />
    </ChartCard>
  </div>

  <div class="row four">
    <ChartCard title="Weakness types" subtitle="CWE of CVEs in P1–P3 stories">
      <HBars rows={overview.cwes.map((c) => ({ key: c.id, label: c.name, value: c.count, title: c.id }))} empty="CWE data fills in as CVE records are fetched." />
    </ChartCard>
    <ChartCard title="CVSS severity" subtitle="CVEs in P1–P3 stories">
      <HBars rows={overview.severity.map((s) => ({ key: s.label, label: s.label, value: s.count }))} labelWidth="narrow" />
    </ChartCard>
    <ChartCard title="Exploit likelihood (EPSS)" subtitle="Probability of exploitation in 30 days">
      <HBars rows={overview.epssBins.map((s) => ({ key: s.label, label: s.label, value: s.count }))} labelWidth="narrow" />
    </ChartCard>
    <ChartCard title="Source mix" subtitle="Feed items → P1–P3 stories, 14 days">
      <HBars rows={overview.groups.map((g) => ({ key: g.group, label: GROUP_LABELS[g.group], value: g.items, note: `→ ${g.stories}` }))} onSelect={(r) => onFilter(q('group', r.key))} />
    </ChartCard>
  </div>
</div>

<style>
  .overview {
    height: 100%;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    background: var(--page);
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
  }
  .row {
    display: grid;
    gap: 12px;
  }
  .map-row {
    grid-template-columns: minmax(0, 2.2fr) minmax(260px, 1fr);
  }
  .two {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .three {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .four {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .seg {
    display: inline-flex;
    padding: 2px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--page);
  }
  .seg button {
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--muted);
  }
  .seg button.on {
    background: var(--surface-3);
    color: var(--text);
  }
  .actors {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .actors button {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 30px auto 26px;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 4px;
    border-radius: 4px;
    text-align: left;
    font-size: 12.5px;
  }
  .actors button:hover {
    background: var(--surface-2);
  }
  .a-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .a-origin {
    font: 11px ui-monospace, SFMono-Regular, Consolas, monospace;
    color: var(--muted);
    text-align: center;
  }
  .a-n {
    text-align: right;
    font-weight: 600;
  }
  .rw-sum {
    margin: 0 0 6px;
    font-size: 12.5px;
    color: var(--text-2);
  }
  .rw-sum + .actors + .rw-sum {
    margin-top: 6px;
  }
  @media (max-width: 1200px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .map-row,
    .two,
    .three,
    .four {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
