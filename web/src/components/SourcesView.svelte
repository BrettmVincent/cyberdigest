<script lang="ts">
  import type { Health, Meta, SourceInfo } from '../../../shared/types';
  import { GROUP_LABELS } from '../../../shared/types';
  import { ago, fmtDate, fmtDateTime, safeHref } from '../lib/format';

  interface Props {
    meta: Meta;
    health: Health;
    sources: SourceInfo[];
    now: number;
  }
  let { meta, health, sources, now }: Props = $props();
  const useLabel = { data: 'Data', aggregate: 'Counts only', link: 'Linked' } as const;

  const statusLabel = { ok: 'OK', 'not-modified': 'OK (unchanged)', error: 'Failing' } as const;
</script>

<div class="scroll view">
  <section class="intro">
    <h2>Sources &amp; pipeline</h2>
    <p class="muted">
      Updated {fmtDateTime(meta.generatedAt)} in {(meta.durationMs / 1000).toFixed(0)}s · history since {fmtDate(meta.stateSince)} ·
      KEV catalog {meta.data.kevCatalogVersion ?? 'n/a'} ({meta.data.kevCount} entries) · EPSS {meta.data.epssDate ?? 'n/a'} ({meta.data.epssModel ?? 'n/a'})
    </p>
  </section>

  <section id="credits">
    <h3>Data sources &amp; credits</h3>
    <p class="muted small">
      Everything CyberDigest shows comes from these sources. Ransomware data is published as counts only: no victim names, logos, chats or
      ransom-note text. Services used only as links (VirusTotal, Censys, X, wallet explorers) receive no data and are not listed.
    </p>
    <table class="data">
      <thead><tr><th>Source</th><th>Use</th><th>Licence / terms</th><th>Credit &amp; changes</th><th>Status</th><th class="num">Updated</th></tr></thead>
      <tbody>
        {#each sources as s (s.id)}
          {@const href = safeHref(s.url)}
          <tr>
            <td>{#if href}<a href={href} target="_blank" rel="noopener noreferrer">{s.name}</a>{:else}{s.name}{/if}</td>
            <td class="muted">{useLabel[s.use]}</td>
            <td class="text-2">{s.license}</td>
            <td class="text-2">{s.credit}<div class="muted small">{s.changes}</div></td>
            <td title={s.detail}>
              <span class="badge" class:kev={s.status === 'error'} class:warn={s.status === 'stale'}>{s.status.toUpperCase()}</span>
              <div class="muted small detail">{s.detail}</div>
            </td>
            <td class="num muted">{s.retrievedAt ? ago(s.retrievedAt, now) : '—'}{#if s.version}<div class="small">{s.version}</div>{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <section>
    <h3>Feeds <span class="muted num">({meta.counts.feedsOk}/{meta.counts.feedsTotal} OK)</span></h3>
    <table class="data">
      <thead>
        <tr>
          <th>Feed</th><th>Tier</th><th>Group</th><th>Status</th><th class="num">Items/7d</th><th class="num">Newest item</th><th class="num">Last OK</th><th>Notes</th>
        </tr>
      </thead>
      <tbody>
        {#each health.feeds as f (f.id)}
          <tr>
            <td><span title={f.url}>{f.name}</span></td>
            <td><span class="badge tier">{f.tier}</span></td>
            <td class="text-2">{GROUP_LABELS[f.group]}</td>
            <td>
              <span class="badge" class:kev={f.status === 'error'}>{statusLabel[f.status]}</span>
              {#if f.consecutiveFailures > 1}<span class="muted num"> ×{f.consecutiveFailures}</span>{/if}
            </td>
            <td class="num">{f.itemsPerWeek}</td>
            <td class="num muted">{f.newestItem ? ago(f.newestItem, now) : '—'}</td>
            <td class="num muted">{f.lastOk ? ago(f.lastOk, now) : 'never'}</td>
            <td class="text-2">
              {#if f.error}{f.error}{/if}
              {#if f.possibleGap}<span class="badge warn" title="Every item was new: the feed's window may have scrolled past items between runs">possible gap</span>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <section class="muted about">
    <h3>About the data</h3>
    <p>
      Stories are clustered from {meta.counts.feedsTotal} curated feeds: same CVE in both headlines, overlapping CVE sets, or near-identical headlines
      from different outlets. Priority comes from ordered rules (CISA KEV, CISA SSVC, EPSS, public PoC, advisory exploitation language, multi-source
      coverage), never from a blended score; each story lists the reasons that fired. Enrichment: CISA KEV, FIRST EPSS, CVE Program cvelistV5 (incl. CISA-ADP
      SSVC), nomi-sec PoC-in-GitHub, MISP galaxy / MITRE ATT&amp;CK names. PoC repositories are counted, not linked: many contain malware.
    </p>
  </section>
</div>

<style>
  .view {
    height: 100%;
    padding: 16px 20px 40px;
  }
  h2 {
    margin: 0 0 4px;
    font-size: 16px;
  }
  h3 {
    margin: 22px 0 8px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  .intro p {
    margin: 0;
  }
  .about p {
    max-width: 80ch;
  }
  .small {
    font-size: 11px;
  }
  .detail {
    max-width: 260px;
  }
  td a {
    color: var(--accent);
  }
</style>
