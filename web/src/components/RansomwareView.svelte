<script lang="ts">
  import type { RansomwareData, SourceInfo } from '../../../shared/types';
  import { epssText, fmtDate } from '../lib/format';
  import { rtmUrl, rvmUrl } from '../lib/links';
  import { q } from '../lib/query';
  import ChartCard from './charts/ChartCard.svelte';
  import HBars from './charts/HBars.svelte';
  import StackedBars, { type Series } from './charts/StackedBars.svelte';
  import StatTile from './charts/StatTile.svelte';
  import Sparkline from './Sparkline.svelte';

  interface Props {
    data: RansomwareData;
    sources: SourceInfo[];
    onGroup: (id: string) => void;
    onFilter: (token: string) => void;
  }
  let { data, sources, onGroup, onFilter }: Props = $props();

  const src = (id: string) => sources.find((s) => s.id === id);
  const shortDay = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });
  const rl = $derived(data.totals.ransomlook);
  const live = $derived(data.totals.ransomwareLive);
  const active = $derived(data.groups.filter((g) => g.last30 > 0).slice(0, 12));
  const flipsRecent = $derived(data.kevFlips.length);
  const rvmInKev = $derived(data.rvmCves.filter((c) => c.kev).length);
  let cveLimit = $state(25);

  const series = (values: number[] | null, label: string, cls: string): Series[] => (values ? [{ key: label, label, cls, values }] : []);
  const countryLabel = $derived(data.countrySource === 'ransomware.live' ? 'Leak-site claims by victim country (Ransomware.live)' : 'Publicly reported cyberattacks by country (Cyberwatch)');
</script>

<div class="scroll rw">
  <header class="head">
    <div>
      <h1>Ransomware</h1>
      <p class="caveat" role="note"><span class="badge warn">Caveat</span> {data.caveat}</p>
    </div>
  </header>

  <div class="tiles">
    {#if rl}<StatTile label="Leak-site claims (7d)" value={rl.last7} previous={rl.prev7} hint="Posts on ransomware leak sites, counted by RansomLook (CC BY 4.0)" />{/if}
    {#if rl}<StatTile label="Active groups (7d)" value={rl.groups7} previous={rl.groupsPrev7 ?? null} note="groups with a post this week" hint="Groups with at least one leak-site post in the last 7 days" />{/if}
    <StatTile label="KEV newly ransomware-linked" value={flipsRecent} previous={null} note="last 60 days (tracked since first run)" hint="CVEs CISA silently flipped to 'known ransomware use'" />
    <StatTile label="CVEs used by ransomware (RVM)" value={data.rvmCves.length} previous={null} note="{rvmInKev} in CISA KEV · click for the list" hint="Ransomware Vulnerability Matrix by Will Thomas" onSelect={() => document.getElementById('rvm-cves')?.scrollIntoView({ behavior: 'smooth' })} />
  </div>

  <div class="row two">
    <ChartCard title="Leak-site claims per week" subtitle="Last 12 weeks (final bar = week to date) · RansomLook{live ? ' and Ransomware.live shown separately (never summed)' : ''}">
      {#snippet table()}
        <table class="data">
          <thead><tr><th>Week of</th><th class="num">RansomLook</th>{#if data.weekly.ransomwareLive}<th class="num">Ransomware.live</th>{/if}</tr></thead>
          <tbody>
            {#each [...data.weeks].reverse() as w, i (w)}
              {@const idx = data.weeks.length - 1 - i}
              <tr><td>{w}</td><td class="num">{data.weekly.ransomlook?.[idx] ?? '—'}</td>{#if data.weekly.ransomwareLive}<td class="num">{data.weekly.ransomwareLive[idx]}</td>{/if}</tr>
            {/each}
          </tbody>
        </table>
      {/snippet}
      {#if data.weekly.ransomlook}
        <StackedBars labels={data.weeks} series={series(data.weekly.ransomlook, 'RansomLook posts', 'f-s1')} tickEvery={3} formatLabel={shortDay} height={170} ariaLabel="Leak-site posts per week (RansomLook)" />
        <p class="credit">{src('ransomlook')?.credit}</p>
      {/if}
      {#if data.weekly.ransomwareLive}
        <StackedBars labels={data.weeks} series={series(data.weekly.ransomwareLive, 'Ransomware.live claims', 'f-s1')} tickEvery={3} formatLabel={shortDay} height={150} ariaLabel="Claims per week (Ransomware.live)" />
        <p class="credit">Source: <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer">Ransomware.live</a></p>
      {/if}
      {#if !data.weekly.ransomlook && !data.weekly.ransomwareLive}<p class="muted">No activity data yet.</p>{/if}
      {#each data.annotations as a (a.week)}
        <p class="note">Week of {shortDay(a.week)}: <b>{a.group}</b> posted {Math.round(a.share * 100)}% of claims, often a single mass-exploitation campaign that distorts totals.</p>
      {/each}
    </ChartCard>

    <ChartCard title="Most active groups" subtitle="Posts per week, 12 weeks · click for profile">
      {#if active.length === 0}
        <p class="muted">No activity data yet.</p>
      {:else}
        <ul class="groups">
          {#each active as g (g.id)}
            <li>
              <button onclick={() => onGroup(g.id)}>
                <span class="g-name">{g.name}</span>
                <Sparkline values={g.weekly} days={data.weeks} baseline={null} label={g.name} width={110} height={20} />
                <span class="num g-n" title="Posts in the last 7 / 30 days">{g.last7} <span class="muted">/ {g.last30}</span></span>
              </button>
            </li>
          {/each}
        </ul>
        <p class="note">Shown as trends, not a leaderboard: groups that are paid quickly never post their victims.</p>
      {/if}
    </ChartCard>
  </div>

  <div class="row two">
    {#if data.sectors.length}
      <ChartCard title="Sectors" subtitle="Claims by victim sector, 30 days (Ransomware.live)">
        <HBars rows={data.sectors.map((s) => ({ key: s.name, label: s.name, value: s.count }))} />
        <p class="credit">Source: <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer">Ransomware.live</a></p>
      </ChartCard>
    {/if}
    {#if data.countries.length}
      <ChartCard title="Countries" subtitle={`${countryLabel}, 30 days`}>
        <HBars rows={data.countries.slice(0, 12).map((c) => ({ key: c.iso, label: c.name, value: c.count }))} />
        <p class="credit">{data.countrySource === 'ransomware.live' ? 'Source: Ransomware.live' : src('cyberwatch')?.credit}</p>
      </ChartCard>
    {/if}
    <ChartCard title="KEV newly linked to ransomware" subtitle="CISA flipped known ransomware use from Unknown to Known">
      {#if data.kevFlips.length === 0}
        <p class="muted">No flips observed yet. CyberDigest compares the KEV catalog on every run; flips appear here as CISA makes them.</p>
      {:else}
        <ul class="mini-list">
          {#each data.kevFlips as f (f.cve)}
            <li><button onclick={() => onFilter(q('cve', f.cve))}><span class="mono">{f.cve}</span> <span class="muted">{fmtDate(f.date)}</span><span class="text-2">{f.vendor} {f.product}: {f.name}</span></button></li>
          {/each}
        </ul>
      {/if}
    </ChartCard>
  </div>

  <ChartCard title="CVEs exploited by ransomware groups" subtitle="Ransomware Vulnerability Matrix (Will Thomas, CC BY 4.0) · updated {fmtDate(data.matrixUpdated.rvm ?? undefined) || 'n/a'} · a missing CVE means 'not recorded', not 'not used'">
    <div id="rvm-cves" class="scroll tbl">
      <table class="data">
        <thead><tr><th>CVE</th><th>Product</th><th>Groups</th><th>KEV</th><th class="num">EPSS</th><th class="num">CVSS</th><th class="num">Detections</th></tr></thead>
        <tbody>
          {#each data.rvmCves.slice(0, cveLimit) as c (c.cve)}
            <tr>
              <td><button class="chip mono" onclick={() => onFilter(q('cve', c.cve))}>{c.cve}</button></td>
              <td class="text-2">{c.vendor ? `${c.vendor} · ` : ''}{c.product}</td>
              <td>
                {#each c.groups as g, i (g)}<button class="link" onclick={() => onGroup(g)}>{g}</button>{i < c.groups.length - 1 ? ', ' : ''}{/each}
              </td>
              <td>{#if c.kev}<span class="badge kev">{c.kevRansomware ? 'KEV · ransomware' : 'KEV'}</span>{:else}—{/if}</td>
              <td class="num">{epssText(c.epss, c.epssPct)}</td>
              <td class="num">{c.cvss?.toFixed(1) ?? '—'}</td>
              <td class="num">{c.detections || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if data.rvmCves.length > cveLimit}<div class="more"><button class="btn small" onclick={() => (cveLimit += 50)}>Show more ({data.rvmCves.length - cveLimit})</button></div>{/if}
    </div>
    <p class="credit">Ransomware Vulnerability Matrix by Will Thomas (BushidoUK), <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>, parsed and normalised by CyberDigest · <a href={rvmUrl} target="_blank" rel="noopener noreferrer">source ↗</a></p>
  </ChartCard>

  <ChartCard title="Hunt for these tools" subtitle="Tools used by this month's most active groups (Ransomware Tool Matrix)">
    <p class="note">Many are legitimate IT tools: investigate before blocking (author's guidance).</p>
    {#if data.hunting.length === 0}
      <p class="muted">No tool data for the current top groups.</p>
    {:else}
      <div class="hunt">
        {#each data.hunting as cat (cat.category)}
          <section>
            <h3>{cat.category}</h3>
            <ul>
              {#each cat.tools as t (t.name)}
                <li><b>{t.name}</b> <span class="muted">{t.groups.join(', ')}</span></li>
              {/each}
            </ul>
          </section>
        {/each}
      </div>
    {/if}
    <p class="credit">Ransomware Tool Matrix by Will Thomas (BushidoUK), CC BY 4.0, parsed and normalised by CyberDigest · <a href={rtmUrl} target="_blank" rel="noopener noreferrer">source ↗</a></p>
  </ChartCard>
</div>

<style>
  .rw {
    height: 100%;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    background: var(--page);
  }
  h1 {
    margin: 0;
    font-size: 20px;
  }
  .caveat {
    margin: 6px 0 0;
    color: var(--text-2);
    font-size: 12.5px;
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
  .two {
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  }
  .groups {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .groups button {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto 64px;
    gap: 10px;
    align-items: center;
    width: 100%;
    padding: 4px;
    border-radius: 4px;
    text-align: left;
  }
  .groups button:hover {
    background: var(--surface-2);
  }
  .g-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .g-n {
    text-align: right;
    font-weight: 600;
  }
  .note {
    margin: 8px 0 0;
    font-size: 11.5px;
    color: var(--muted);
  }
  .credit {
    margin: 6px 0 0;
    font-size: 11px;
    color: var(--muted);
  }
  .credit a,
  .link {
    color: var(--accent);
    font: inherit;
  }
  .link:hover {
    text-decoration: underline;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 12px;
  }
  .mini-list li button {
    display: flex !important;
    flex-wrap: wrap;
    gap: 4px 8px;
  }
  .tbl {
    max-height: 420px;
  }
  .more {
    padding: 8px;
    text-align: center;
  }
  .hunt {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 10px 18px;
    margin-top: 8px;
  }
  .hunt h3 {
    margin: 0 0 4px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  .hunt ul {
    list-style: none;
    margin: 0;
    padding: 0;
    font-size: 12px;
  }
  .hunt li {
    padding: 2px 0;
  }
  @media (max-width: 1100px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
</style>
