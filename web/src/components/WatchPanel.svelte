<script lang="ts">
  import type { Story } from '../../../shared/types';
  import { ago } from '../lib/format';
  import { prefs } from '../lib/prefs.svelte';

  interface Props {
    hits: Story[];
    now: number;
    onSelect: (id: string) => void;
    onManage: () => void;
    onShowAll: () => void;
  }
  let { hits, now, onSelect, onManage, onShowAll }: Props = $props();
</script>

<section class="panel" aria-labelledby="w-h">
  <header>
    <h2 id="w-h">Watchlist</h2>
    <button class="btn small" onclick={onManage}>Manage</button>
  </header>
  {#if prefs.watch.length === 0}
    <p class="empty">Watch vendors, products, actors, CVEs or keywords from your stack. Use ☆ in a story's detail pane, or <b>Manage</b>.</p>
  {:else if hits.length === 0}
    <p class="empty">No stories match your {prefs.watch.length} watched {prefs.watch.length === 1 ? 'term' : 'terms'} in the last 14 days.</p>
  {:else}
    <ul class="mini-list">
      {#each hits.slice(0, 6) as s (s.id)}
        <li>
          <button onclick={() => onSelect(s.id)}>
            <span class="l1"><span class="prio p{s.priority}">P{s.priority}</span><span class="age num">{ago(s.lastSeen, now)}</span></span>
            <span class="t">{s.title}</span>
          </button>
        </li>
      {/each}
    </ul>
    {#if hits.length > 6}<div class="foot"><button class="btn small" onclick={onShowAll}>All {hits.length} matches</button></div>{/if}
  {/if}
</section>

<style>
  .l1 {
    display: flex;
    justify-content: space-between;
  }
  .age {
    color: var(--muted);
    font-size: 11.5px;
  }
  .t {
    font-size: 12.5px;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .foot {
    padding: 0 12px 10px;
  }
</style>
