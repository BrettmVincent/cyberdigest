<script lang="ts">
  import type { EpssMovers } from '../../../shared/types';
  import { deltaText, epssText, fmtDate } from '../lib/format';
  import { q } from '../lib/query';

  interface Props {
    epss: EpssMovers;
    onFilter: (token: string) => void;
  }
  let { epss, onFilter }: Props = $props();

  let onlyRelevant = $state(true);
  const list = $derived(epss.movers.filter((m) => !onlyRelevant || m.stories > 0 || m.kev).slice(0, 12));
  const kindLabel = { jump: 'jump', 'cross-p99': '→ top 1%', 'cross-p95': '→ top 5%' } as const;
</script>

<section class="panel" aria-labelledby="epss-h">
  <header>
    <h2 id="epss-h">EPSS movers</h2>
    <span class="panel-sub">{epss.date ? `${fmtDate(epss.prevDate ?? undefined)} → ${fmtDate(epss.date)}` : 'n/a'}</span>
  </header>
  {#if epss.modelChange}
    <p class="empty">EPSS model updated ({epss.modelChange.from} → {epss.modelChange.to}): scores were re-computed, so day-over-day movers are paused until the next snapshot.</p>
  {:else if !epss.prevDate}
    <p class="empty">Movers appear after the second daily EPSS snapshot.</p>
  {:else}
    <div class="toggle">
      <button class="btn small" aria-pressed={onlyRelevant} onclick={() => (onlyRelevant = !onlyRelevant)}>In stories or KEV only</button>
    </div>
    {#if list.length === 0}
      <p class="empty">No threshold crossings{onlyRelevant ? ' among CVEs in current stories' : ''}.</p>
    {:else}
      <ul class="mini-list">
        {#each list as m (m.cve)}
          <li>
            <button onclick={() => onFilter(q('cve', m.cve))}>
              <span class="l1">
                <span class="mono">{m.cve}</span>
                {#if m.kev}<span class="badge kev">KEV</span>{/if}
                <span class="kind">{m.kind === 'jump' ? deltaText(m.delta) : kindLabel[m.kind]}</span>
              </span>
              <span class="l2 num">
                {m.prevEpss != null ? `${epssText(m.prevEpss, m.prevPct)} → ` : 'new · '}{epssText(m.epss, m.pct)}
                {#if m.stories}· {m.stories} {m.stories === 1 ? 'story' : 'stories'}{/if}
              </span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<style>
  .toggle {
    padding: 0 12px 6px;
  }
  .l1 {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 12px;
  }
  .kind {
    margin-left: auto;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text);
  }
  .l2 {
    color: var(--muted);
    font-size: 11.5px;
  }
</style>
