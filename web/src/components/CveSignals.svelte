<script lang="ts">
  // Ransomware, multi-source exploitation and detection-coverage signals for one CVE.
  import type { CveInfo } from '../../../shared/types';
  import { fmtDate } from '../lib/format';
  import { circlUrl, ghsaUrl, nucleiUrl, osvUrl, ROLE_LABEL, rvmUrl, sigmaUrl } from '../lib/links';

  interface Props {
    info: CveInfo;
    /** Group names open the group profile. */
    onGroup?: (name: string) => void;
    compact?: boolean;
  }
  let { info, onGroup, compact = false }: Props = $props();

  const rw = $derived(info.ransomware);
  const ex = $derived(info.exploitation);
  const det = $derived(info.detections);
  const detTotal = $derived(det ? (det.nuclei ? 1 : 0) + det.sigma.length + det.et.length + det.yara.length : 0);
  const oss = $derived(info.oss?.packages.length ? info.oss : undefined);
  const PKG_SHOWN = 3;
</script>

{#if rw || ex || det || info.detectionGap || oss}
  <div class="signals" class:compact>
    {#if rw}
      <div class="sig">
        <span class="badge kev">Ransomware</span>
        <span class="text">
          {#if rw.kevKnown}Known use (CISA KEV){#if rw.flippedAt} · <b>newly flagged {fmtDate(rw.flippedAt)}</b>{/if}{/if}
          {#if rw.groups.length}
            {rw.kevKnown ? ' · ' : ''}groups:
            {#each rw.groups as g, i (g.name)}
              {#if onGroup}<button class="link" onclick={() => onGroup(g.name)}>{g.name}</button>{:else}<b>{g.name}</b>{/if}{#if ROLE_LABEL[g.role]}<span class="muted"> ({ROLE_LABEL[g.role]})</span>{/if}{i < rw.groups.length - 1 ? ', ' : ''}
            {/each}
            {#if !compact}<a class="src" href={rvmUrl} target="_blank" rel="noopener noreferrer">RVM ↗</a>{/if}
          {/if}
        </span>
      </div>
    {/if}
    {#if ex}
      <div class="sig">
        <span class="badge" class:warn={ex.catalogs.length > 0 || ex.exploited30d > 0}>Exploitation</span>
        <span class="text">
          {#if ex.catalogs.length}listed by <b>{ex.catalogs.join(', ')}</b>{#if ex.notInCisa} <span class="muted">(not yet in CISA KEV)</span>{/if}{/if}
          {#if ex.exploited30d}{ex.catalogs.length ? ' · ' : ''}{ex.exploited30d} exploitation sightings (30d){/if}
          {#if ex.honeypot7d} · <b>honeypot hits this week</b>{/if}
          {#if ex.poc30d} · {ex.poc30d} PoC posts{/if}
          {#if !compact}<a class="src" href={circlUrl(info.id)} target="_blank" rel="noopener noreferrer">CIRCL ↗</a>{/if}
        </span>
      </div>
    {/if}
    {#if detTotal || det?.rulezet}
      <div class="sig">
        <span class="badge">Detections</span>
        <span class="text">
          {#if det?.nuclei}{#if compact}Nuclei{:else}<a href={nucleiUrl(det.nuclei)} target="_blank" rel="noopener noreferrer">Nuclei ↗</a>{/if}{/if}
          {#if det?.sigma.length}{det.nuclei ? ' · ' : ''}{#if compact}Sigma ×{det.sigma.length}{:else}Sigma: {#each det.sigma.slice(0, 3) as s, i (s.path)}<a href={sigmaUrl(s.path)} target="_blank" rel="noopener noreferrer" title={s.title}>{i + 1}↗</a>{' '}{/each}{/if}{/if}
          {#if det?.et.length}{det.nuclei || det.sigma.length ? ' · ' : ''}<span title={det.et.map((e) => `${e.sid}: ${e.msg}`).join('\n')}>ET Open ×{det.et.length}</span>{/if}
          {#if det?.yara.length} · <span title={det.yara.join('\n')}>YARA ×{det.yara.length}</span>{/if}
          {#if det?.rulezet} · {#if compact}Rulezet ×{det.rulezet}{:else}<a href={circlUrl(info.id)} target="_blank" rel="noopener noreferrer">Rulezet ×{det.rulezet} ↗</a>{/if}{/if}
        </span>
      </div>
    {/if}
    {#if oss}
      <div class="sig">
        <span class="badge">Open source</span>
        <span class="text">
          {#each oss.packages.slice(0, compact ? 2 : PKG_SHOWN) as p, i (p.ecosystem + p.name)}
            {i ? ' · ' : ''}<span class="muted">{p.ecosystem}</span> <b>{p.name}</b>
            {#if p.fixed}<span title="First patched version (GitHub Advisory Database)"> → fixed {p.fixed}</span>{:else}<span class="muted"> → no fix listed</span>{/if}
          {/each}
          {#if oss.packages.length > (compact ? 2 : PKG_SHOWN)}<span class="muted"> · +{oss.packages.length - (compact ? 2 : PKG_SHOWN)} more</span>{/if}
          {#if !compact}
            {#if oss.ghsa}<a class="src" href={ghsaUrl(oss.ghsa)} target="_blank" rel="noopener noreferrer">GitHub Advisory ↗</a>{/if}
            {#if oss.osv}<a class="src" href={osvUrl(info.id)} target="_blank" rel="noopener noreferrer" title={oss.related ? `${oss.related} related advisories on OSV.dev` : 'OSV.dev'}>OSV{oss.related ? ` (+${oss.related})` : ''} ↗</a>{/if}
          {/if}
        </span>
      </div>
    {/if}
    {#if info.detectionGap}
      <div class="sig"><span class="badge gap">Detection gap</span><span class="text muted">exploited, but no public Nuclei / Sigma / ET / YARA rule found</span></div>
    {/if}
  </div>
{/if}

<style>
  .signals {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 6px;
    font-size: 12px;
  }
  .sig {
    display: grid;
    grid-template-columns: 96px 1fr;
    gap: 8px;
    align-items: baseline;
  }
  .compact .sig {
    grid-template-columns: 84px 1fr;
    font-size: 11.5px;
  }
  .text {
    color: var(--text-2);
  }
  .text a,
  .link {
    color: var(--accent-ink);
  }
  .link {
    font: inherit;
  }
  .link:hover {
    text-decoration: underline;
  }
  .src {
    margin-left: 6px;
    font-size: 11px;
  }
  .badge.gap {
    border-color: var(--warning);
    border-style: dashed;
    color: var(--text);
  }
</style>
