<script lang="ts">
  import type { ActorProfile, Story } from '../../../shared/types';
  import { ago } from '../lib/format';
  import { prefs, term, toggleIn } from '../lib/prefs.svelte';
  import { q } from '../lib/query';
  import ChartCard from './charts/ChartCard.svelte';
  import HBars from './charts/HBars.svelte';
  import WorldMap from './charts/WorldMap.svelte';
  import Sparkline from './Sparkline.svelte';

  interface Props {
    actor: ActorProfile;
    storyById: Map<string, Story>;
    trendDays: string[];
    now: number;
    onBack: () => void;
    onFilter: (token: string) => void;
    onStory: (id: string) => void;
  }
  let { actor, storyById, trendDays, now, onBack, onFilter, onStory }: Props = $props();

  const watchTerm = $derived(term('actor', actor.name));
  const watching = $derived(prefs.watch.includes(watchTerm));
  const stories = $derived(actor.stories.map((id) => storyById.get(id)).filter((s): s is Story => Boolean(s)));
  const profile = $derived({ origin: actor.countryNumeric, targets: actor.targets.map((t) => t.numeric).filter((n): n is string => Boolean(n)) });
</script>

<div class="scroll actor-view">
  <header class="head">
    <button class="btn small" onclick={onBack}>← Back</button>
    <div class="title">
      <h1>{actor.name}</h1>
      <div class="facts">
        {#if actor.countryName}<span class="badge" title="Suspected origin (MISP galaxy attribution)">Origin: {actor.countryName}</span>{:else}<span class="badge">Origin unattributed</span>{/if}
        {#if actor.motive}<span class="badge">{actor.motive}</span>{/if}
        <span class="muted">last seen {ago(actor.lastSeen, now)} ago</span>
      </div>
    </div>
    <div class="head-actions">
      <button class="btn small" aria-pressed={watching} onclick={() => toggleIn(prefs.watch, watchTerm)}>{watching ? '★ Watching' : '☆ Watch'}</button>
      <button class="btn small" onclick={() => onFilter(q('actor', actor.name))}>All stories</button>
    </div>
  </header>

  {#if actor.aliases.length}
    <p class="aliases"><span class="muted">Also known as</span> {#each actor.aliases as a (a)}<span class="chip">{a}</span>{/each}</p>
  {/if}
  {#if actor.description}<p class="desc">{actor.description}</p>{/if}

  <div class="grid">
    <div class="col">
      <ChartCard title="Activity" subtitle="Stories per day, 30 days">
        <div class="activity">
          <Sparkline values={actor.days} days={trendDays} baseline={null} label={actor.name} width={300} height={56} />
          <div class="nums">
            <div><b class="num">{actor.last7}</b><span class="muted">last 7 days</span></div>
            <div><b class="num">{actor.total30}</b><span class="muted">last 30 days</span></div>
          </div>
        </div>
      </ChartCard>
      <ChartCard title="Mentioned alongside" subtitle="Malware and vendors in the same stories">
        <h3>Malware</h3>
        <HBars rows={actor.malware.map((m) => ({ key: m.name, label: m.name, value: m.count }))} onSelect={(r) => onFilter(q('malware', r.key))} empty="None." />
        <h3>Vendors</h3>
        <HBars rows={actor.vendors.map((m) => ({ key: m.name, label: m.name, value: m.count }))} onSelect={(r) => onFilter(q('vendor', r.key))} empty="None." />
        {#if actor.cves.length}
          <h3>CVEs</h3>
          <div class="cves">{#each actor.cves.slice(0, 16) as c (c)}<button class="chip mono" onclick={() => onFilter(q('cve', c))}>{c}</button>{/each}</div>
        {/if}
      </ChartCard>
    </div>
    <div class="col">
      <ChartCard title="Origin & known targets" subtitle="MISP galaxy profile: reference data, not confirmed incidents">
        {#if actor.countryNumeric || actor.targets.length}
          <WorldMap {profile} ariaLabel="Map of {actor.name}: origin {actor.countryName ?? 'unknown'}; known targets {actor.targets.map((t) => t.name).join(', ') || 'none listed'}" />
        {:else}
          <p class="muted">No attribution or target data in the profile.</p>
        {/if}
        {#if actor.targets.length}
          <p class="targets"><span class="muted">Targets:</span> {actor.targets.map((t) => t.name).join(', ')}</p>
        {/if}
        {#if actor.sectors.length}
          <div class="sectors">{#each actor.sectors as s (s)}<span class="chip">{s}</span>{/each}</div>
        {/if}
      </ChartCard>
    </div>
  </div>

  <section class="panel stories">
    <header><h2>Recent stories</h2><span class="panel-sub num">{stories.length}</span></header>
    <ul class="mini-list">
      {#each stories as s (s.id)}
        <li>
          <button onclick={() => onStory(s.id)}>
            <span class="srow"><span class="prio p{s.priority}">P{s.priority}</span><span class="st">{s.title}</span><span class="muted num">{ago(s.lastSeen, now)}</span></span>
            <span class="muted sfeed">{s.feed}{s.sourceCount > 1 ? ` +${s.sourceCount - 1}` : ''}</span>
          </button>
        </li>
      {:else}
        <li><p class="empty">No stories in the current 14-day window.</p></li>
      {/each}
    </ul>
  </section>
</div>

<style>
  .actor-view {
    height: 100%;
    padding: 16px 20px 40px;
    background: var(--page);
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: 14px;
  }
  .title {
    flex: 1;
  }
  h1 {
    margin: 0;
    font-size: 22px;
    line-height: 1.2;
  }
  .facts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin-top: 6px;
    font-size: 12px;
  }
  .head-actions {
    display: flex;
    gap: 6px;
  }
  .aliases {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
    margin: 14px 0 0;
    font-size: 12px;
  }
  .desc {
    max-width: 100ch;
    color: var(--text-2);
    margin: 12px 0 0;
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.3fr);
    gap: 12px;
    margin-top: 16px;
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 12px;
    min-width: 0;
  }
  .activity {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .nums {
    display: flex;
    gap: 18px;
  }
  .nums div {
    display: flex;
    flex-direction: column;
  }
  .nums b {
    font-size: 22px;
  }
  .nums span {
    font-size: 11.5px;
  }
  h3 {
    margin: 10px 0 4px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  .cves,
  .sectors {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .sectors {
    margin-top: 8px;
  }
  .targets {
    margin: 8px 0 0;
    font-size: 12px;
    color: var(--text-2);
  }
  .stories {
    margin-top: 12px;
  }
  .srow {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    gap: 8px;
    align-items: center;
  }
  .st {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sfeed {
    font-size: 11.5px;
    padding-left: 44px;
  }
  @media (max-width: 1100px) {
    .grid {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
