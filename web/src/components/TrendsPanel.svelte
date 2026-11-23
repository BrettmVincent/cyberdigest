<script lang="ts">
  import type { TrendSeries, Trends } from '../../../shared/types';
  import { q } from '../lib/query';
  import Sparkline from './Sparkline.svelte';

  interface Props {
    trends: Trends;
    onFilter: (token: string) => void;
  }
  let { trends, onFilter }: Props = $props();

  type Tab = 'actors' | 'malware' | 'vendors';
  let tab = $state<Tab>('actors');
  const tabs: { id: Tab; label: string; key: string }[] = [
    { id: 'actors', label: 'Actors', key: 'actor' },
    { id: 'malware', label: 'Malware', key: 'malware' },
    { id: 'vendors', label: 'Vendors', key: 'vendor' },
  ];
  const series = $derived<TrendSeries[]>(trends[tab]);
  const key = $derived(tabs.find((t) => t.id === tab)!.key);
</script>

<section class="panel" aria-labelledby="tr-h">
  <header>
    <h2 id="tr-h">Mention trends</h2>
    <span class="panel-sub">stories/day, 30d</span>
  </header>
  <div class="tabs" role="tablist" aria-label="Entity type">
    {#each tabs as t (t.id)}
      <button role="tab" aria-selected={tab === t.id} class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
    {/each}
  </div>
  {#if series.length === 0}
    <p class="empty">Nothing mentioned in 2+ stories this week.</p>
  {:else}
    <ul class="mini-list" aria-label="{tabs.find((t) => t.id === tab)?.label} trends">
      {#each series as s (s.name)}
        <li>
          <button class="trow" onclick={() => onFilter(q(key, s.name))}>
            <span class="name">
              {s.name}
              {#if s.rising}<span class="badge warn" title="At least double its usual weekly rate">↑ rising</span>{/if}
            </span>
            <Sparkline values={s.days} days={trends.days} baseline={s.baseline} label={s.name} />
            <span class="nums num" title="Stories in the last 7 days vs the usual weekly rate">
              <b>{s.last7}</b>
              <span class="muted">{s.baseline === null ? '' : `vs ${s.baseline}`}</span>
            </span>
          </button>
        </li>
      {/each}
    </ul>
    <p class="note">
      Line: stories per day. Dashed: usual daily rate{trends.historyDays < 14 ? ` (baseline builds after 14 days of history; ${trends.historyDays}d so far)` : ''}.
    </p>
  {/if}
</section>

<style>
  .tabs {
    display: flex;
    gap: 2px;
    padding: 0 12px 6px;
  }
  .tabs button {
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--muted);
  }
  .tabs button.active {
    background: var(--surface-3);
    color: var(--text);
  }
  .trow {
    grid-template-columns: minmax(0, 1fr) auto 52px;
    align-items: center;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
    font-size: 12.5px;
  }
  .nums {
    text-align: right;
    font-size: 12px;
  }
  .nums .muted {
    display: block;
    font-size: 10.5px;
  }
  .note {
    margin: 0;
    padding: 0 12px 10px;
    color: var(--muted);
    font-size: 11px;
  }
</style>
