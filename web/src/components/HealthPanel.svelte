<script lang="ts">
  import type { Health, Meta } from '../../../shared/types';

  interface Props {
    meta: Meta;
    health: Health;
    onOpen: () => void;
  }
  let { meta, health, onOpen }: Props = $props();

  const failing = $derived(health.feeds.filter((f) => f.status === 'error'));
  const enrichIssues = $derived(health.enrichment.filter((e) => e.status !== 'ok'));
</script>

<section class="panel" aria-labelledby="h-h">
  <header>
    <h2 id="h-h">Pipeline health</h2>
    <button class="btn small" onclick={onOpen}>Details</button>
  </header>
  <ul class="mini-list">
    <li>
      <div class="row">
        <span>Feeds</span>
        <span class="num"><b>{meta.counts.feedsOk}</b>/{meta.counts.feedsTotal} OK</span>
      </div>
    </li>
    {#each failing.slice(0, 4) as f (f.id)}
      <li><div class="row sub"><span>⚠ {f.name}</span><span class="muted">{f.error ?? `HTTP ${f.httpStatus}`}</span></div></li>
    {/each}
    <li>
      <div class="row">
        <span>Enrichment</span>
        <span>{enrichIssues.length === 0 ? 'all OK' : `${enrichIssues.length} issue${enrichIssues.length > 1 ? 's' : ''}`}</span>
      </div>
    </li>
    {#each enrichIssues as e (e.name)}
      <li><div class="row sub"><span>⚠ {e.name}</span><span class="muted">{e.status}</span></div></li>
    {/each}
    <li>
      <div class="row">
        <span>Noise removed</span>
        <span class="num" title="Items folded into multi-source stories over 14 days">{meta.counts.items} items → {meta.counts.stories} stories</span>
      </div>
    </li>
  </ul>
</section>

<style>
  .row {
    display: flex !important;
    justify-content: space-between;
    gap: 8px;
    font-size: 12.5px;
  }
  .row.sub {
    font-size: 11.5px;
    padding-top: 0 !important;
  }
  .row.sub span:first-child {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
