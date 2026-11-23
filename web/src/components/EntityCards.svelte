<script lang="ts" module>
  // Hover-card bodies for CVEs and threat actors, shared by the story list and detail pane.
  import type { ActorProfile, CveInfo } from '../../../shared/types';
  import { epssText, fmtDate } from '../lib/format';
  import CveSignals from './CveSignals.svelte';
  export { cveCard, actorCard };
</script>

{#snippet cveCard(id: string, c: CveInfo | undefined)}
  <div class="ec">
    <div class="ec-h"><b class="mono">{id}</b>{#if c?.kev}<span class="badge kev">KEV</span>{/if}{#if c?.kev?.ransomware}<span class="badge kev">Ransomware</span>{/if}</div>
    {#if c}
      {#if c.vendor || c.product}<div class="ec-prod">{[c.vendor, c.product].filter(Boolean).join(' · ')}</div>{/if}
      <div class="ec-stats num">
        <span>CVSS <b>{c.cvss?.toFixed(1) ?? 'n/a'}</b></span>
        <span>EPSS <b>{epssText(c.epss, c.epssPct)}</b></span>
        {#if c.poc}<span>PoC <b>×{c.poc.count}</b></span>{/if}
      </div>
      {#if c.kev}<div class="ec-line">KEV since {fmtDate(c.kev.dateAdded)} · due {fmtDate(c.kev.dueDate)}</div>{/if}
      {#if c.ssvc?.exploitation}<div class="ec-line">SSVC: exploitation {c.ssvc.exploitation}{c.ssvc.automatable === 'yes' ? ', automatable' : ''}</div>{/if}
      <CveSignals info={c} compact />
      {#if c.description}<p class="ec-desc">{c.description}</p>{/if}
      <div class="ec-line muted">In {c.stories.length} {c.stories.length === 1 ? 'story' : 'stories'} · {c.sources} feeds</div>
    {:else}
      <div class="ec-line muted">No enrichment yet: the CVE record may not be published or fetched.</div>
    {/if}
  </div>
{/snippet}

{#snippet actorCard(name: string, a: ActorProfile | undefined)}
  <div class="ec">
    <div class="ec-h"><b>{name}</b>{#if a?.countryName}<span class="badge">{a.countryName}</span>{/if}</div>
    {#if a}
      {#if a.aliases.length}<div class="ec-line">aka {a.aliases.slice(0, 5).join(', ')}</div>{/if}
      {#if a.motive}<div class="ec-line">{a.motive}</div>{/if}
      {#if a.description}<p class="ec-desc">{a.description}</p>{/if}
      <div class="ec-line muted">{a.last7} stories this week · {a.total30} in 30 days · click for profile</div>
    {/if}
  </div>
{/snippet}

<style>
  .ec {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .ec-h {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text);
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  }
  .ec-prod {
    color: var(--text);
  }
  .ec-stats {
    display: flex;
    gap: 12px;
  }
  .ec-stats b {
    color: var(--text);
    font-weight: 600;
  }
  .ec-desc {
    margin: 0;
    display: -webkit-box;
    -webkit-line-clamp: 4;
    line-clamp: 4;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .ec-line {
    font-size: 11.5px;
  }
</style>
