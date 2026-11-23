<script lang="ts">
  import type { KevEntry } from '../../../shared/types';
  import { daysUntil, epssText } from '../lib/format';
  import { q } from '../lib/query';

  interface Props {
    kev: KevEntry[];
    now: number;
    onFilter: (token: string) => void;
  }
  let { kev, now, onFilter }: Props = $props();

  let showAll = $state(false);
  const recent = $derived(kev.filter((k) => daysUntil(k.dateAdded, now) >= -14));
  const shown = $derived((showAll ? kev : recent).slice(0, showAll ? 50 : 10));
</script>

<section class="panel" aria-labelledby="kev-h">
  <header>
    <h2 id="kev-h">New in CISA KEV</h2>
    <span class="panel-sub num">{recent.length} in 14d</span>
  </header>
  {#if shown.length === 0}
    <p class="empty">No KEV additions in the last 14 days.</p>
  {:else}
    <ul class="mini-list">
      {#each shown as k (k.cve)}
        {@const added = -daysUntil(k.dateAdded, now)}
        {@const due = daysUntil(k.dueDate, now)}
        <li>
          <button onclick={() => onFilter(q('cve', k.cve))} title="{k.name}: {k.shortDescription}">
            <span class="l1">
              <span class="mono">{k.cve}</span>
              {#if k.ransomware}<span class="badge kev" title="Known use in ransomware campaigns">Ransomware</span>{/if}
              <span class="age num">{added === 0 ? 'today' : `${added}d ago`}</span>
            </span>
            <span class="l2">{k.vendor} {k.product}</span>
            <span class="l3 num">
              <span class:urgent={due <= 3}>{due < 0 ? `${-due}d overdue` : due === 0 ? 'due today' : `due in ${due}d`}</span>
              · EPSS {epssText(k.epss, k.epssPct)}
              {#if k.stories}· {k.stories} {k.stories === 1 ? 'story' : 'stories'}{/if}
            </span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}
  {#if kev.length > recent.length}
    <div class="foot"><button class="btn small" onclick={() => (showAll = !showAll)}>{showAll ? 'Last 14 days only' : 'Show latest 50'}</button></div>
  {/if}
</section>

<style>
  .l1 {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 12px;
    color: var(--text);
  }
  .age {
    margin-left: auto;
    color: var(--muted);
    font-size: 11.5px;
  }
  .l2 {
    color: var(--text-2);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .l3 {
    color: var(--muted);
    font-size: 11.5px;
  }
  .urgent {
    color: var(--text);
    font-weight: 600;
    text-decoration: underline;
    text-decoration-color: var(--critical);
    text-decoration-thickness: 2px;
    text-underline-offset: 2px;
  }
  .foot {
    padding: 0 12px 10px;
  }
</style>
