<script lang="ts">
  import type { CveInfo } from '../../../shared/types';
  import { epssText } from '../lib/format';
  import { q } from '../lib/query';

  interface Props {
    cves: CveInfo[];
    now: number;
    onFilter: (token: string) => void;
  }
  let { cves, now, onFilter }: Props = $props();

  // CVEs covered by several independent feeds in the last 7 days: CyberDigest's own "trending" signal.
  const list = $derived(
    cves
      .filter((c) => c.sources >= 2 && now - Date.parse(c.lastSeen) <= 7 * 86_400_000)
      .sort((a, b) => b.sources - a.sources || (b.epss ?? -1) - (a.epss ?? -1))
      .slice(0, 10),
  );
  const max = $derived(Math.max(1, ...list.map((c) => c.sources)));
</script>

<section class="panel" aria-labelledby="ms-h">
  <header>
    <h2 id="ms-h">Most-covered CVEs</h2>
    <span class="panel-sub">independent feeds, 7d</span>
  </header>
  {#if list.length === 0}
    <p class="empty">No CVE is covered by more than one feed this week.</p>
  {:else}
    <ul class="mini-list">
      {#each list as c (c.id)}
        <li>
          <button onclick={() => onFilter(q('cve', c.id))} title={c.description}>
            <span class="l1">
              <span class="mono">{c.id}</span>
              {#if c.kev}<span class="badge kev">KEV</span>{/if}
              <span class="n num">{c.sources}</span>
            </span>
            <svg class="bar" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true">
              <rect class="track" x="0" y="0" width="100" height="4" rx="2" />
              <rect class="fill" x="0" y="0" width={Math.max(4, (c.sources / max) * 100)} height="4" rx="2" />
            </svg>
            <span class="l2">{[c.vendor, c.product].filter(Boolean).join(' · ') || '—'} · EPSS {epssText(c.epss, c.epssPct)}</span>
          </button>
        </li>
      {/each}
    </ul>
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
  }
  .n {
    margin-left: auto;
    font-weight: 600;
  }
  .bar {
    display: block;
    width: 100%;
    height: 4px;
  }
  .bar .track {
    fill: var(--surface-3);
  }
  .bar .fill {
    fill: var(--series-1);
  }
  .l2 {
    color: var(--muted);
    font-size: 11.5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
