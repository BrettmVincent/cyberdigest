<script lang="ts">
  import type { CveInfo } from '../../../shared/types';
  import { ago, daysUntil, deltaText, download, epssText, toCsv } from '../lib/format';
  import { q } from '../lib/query';

  interface Props {
    cves: CveInfo[];
    now: number;
    onFilter: (token: string) => void;
  }
  let { cves, now, onFilter }: Props = $props();

  type SortKey = 'id' | 'cvss' | 'epss' | 'delta' | 'kev' | 'sources' | 'lastSeen';
  let sortKey = $state<SortKey>('lastSeen');
  let desc = $state(true);
  let text = $state('');
  let kevOnly = $state(false);
  let pocOnly = $state(false);
  let epssHigh = $state(false);
  let curatedOnly = $state(true);
  let ransomOnly = $state(false);
  let gapOnly = $state(false);
  let beyondKev = $state(false);
  let limit = $state(200);

  const filtered = $derived.by(() => {
    const t = text.trim().toLowerCase();
    return cves.filter(
      (c) =>
        (!kevOnly || c.kev) &&
        (!pocOnly || c.poc) &&
        (!epssHigh || (c.epss ?? 0) >= 0.088) &&
        (!curatedOnly || c.stories.length > 0) &&
        (!ransomOnly || c.ransomware) &&
        (!gapOnly || c.detectionGap) &&
        (!beyondKev || c.exploitation?.notInCisa) &&
        (!t || [c.id, c.vendor, c.product, c.description].some((x) => x?.toLowerCase().includes(t))),
    );
  });

  const sorted = $derived.by(() => {
    const val = (c: CveInfo): number | string => {
      switch (sortKey) {
        case 'id':
          return c.id;
        case 'cvss':
          return c.cvss ?? -1;
        case 'epss':
          return c.epss ?? -1;
        case 'delta':
          return c.epssDelta ?? -1;
        case 'kev':
          return c.kev?.dateAdded ?? '';
        case 'sources':
          return c.sources;
        case 'lastSeen':
          return c.lastSeen;
      }
    };
    return [...filtered].sort((a, b) => {
      const va = val(a);
      const vb = val(b);
      const r = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb), 'en', { numeric: true });
      return desc ? -r : r;
    });
  });

  function sortBy(k: SortKey) {
    if (sortKey === k) desc = !desc;
    else {
      sortKey = k;
      desc = k !== 'id';
    }
  }

  function exportCsv() {
    const rows = sorted.map((c) => ({
      cve: c.id,
      vendor: c.vendor ?? '',
      product: c.product ?? '',
      cvss: c.cvss ?? '',
      epss: c.epss ?? '',
      epss_percentile: c.epssPct ?? '',
      epss_delta_24h: c.epssDelta ?? '',
      kev_date_added: c.kev?.dateAdded ?? '',
      kev_due_date: c.kev?.dueDate ?? '',
      kev_ransomware: c.kev?.ransomware ? 'yes' : '',
      ssvc_exploitation: c.ssvc?.exploitation ?? '',
      public_poc_repos: c.poc?.count ?? 0,
      ransomware_groups: c.ransomware?.groups.map((g) => g.name).join('; ') ?? '',
      exploited_catalogs: c.exploitation?.catalogs.join('; ') ?? '',
      exploitation_sightings_30d: c.exploitation?.exploited30d ?? 0,
      detections: c.detections ? (c.detections.nuclei ? 1 : 0) + c.detections.sigma.length + c.detections.et.length + c.detections.yara.length : 0,
      detection_gap: c.detectionGap ? 'yes' : '',
      feeds: c.sources,
      last_seen: c.lastSeen,
    }));
    download(`cyberdigest-cves-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(rows), 'text/csv');
  }

  const cols: { k: SortKey; label: string; num?: boolean; title?: string }[] = [
    { k: 'id', label: 'CVE' },
    { k: 'cvss', label: 'CVSS', num: true },
    { k: 'epss', label: 'EPSS (pctl)', num: true, title: 'Probability of exploitation activity in the next 30 days' },
    { k: 'delta', label: 'Δ 24h', num: true },
    { k: 'kev', label: 'KEV', title: 'Date added to CISA KEV' },
    { k: 'sources', label: 'Feeds', num: true, title: 'Independent feeds mentioning it (30d)' },
    { k: 'lastSeen', label: 'Seen', num: true },
  ];
  const ariaSort = (k: SortKey) => (sortKey === k ? (desc ? 'descending' : 'ascending') : 'none');
</script>

<div class="wrap">
  <div class="toolbar">
    <input type="search" placeholder="Filter CVE, vendor, product…" bind:value={text} aria-label="Filter CVEs" />
    <button class="btn small" aria-pressed={curatedOnly} onclick={() => (curatedOnly = !curatedOnly)} title="Hide CVEs only seen in bulk advisory streams">In stories</button>
    <button class="btn small" aria-pressed={kevOnly} onclick={() => (kevOnly = !kevOnly)}>KEV</button>
    <button class="btn small" aria-pressed={epssHigh} onclick={() => (epssHigh = !epssHigh)}>EPSS ≥ 8.8%</button>
    <button class="btn small" aria-pressed={pocOnly} onclick={() => (pocOnly = !pocOnly)}>Public PoC</button>
    <button class="btn small" aria-pressed={ransomOnly} onclick={() => (ransomOnly = !ransomOnly)} title="CISA KEV ransomware flag or Ransomware Vulnerability Matrix">Ransomware</button>
    <button class="btn small" aria-pressed={beyondKev} onclick={() => (beyondKev = !beyondKev)} title="Listed as exploited by ENISA, Shadowserver or others (CIRCL) but not by CISA KEV">Exploited, not in KEV</button>
    <button class="btn small" aria-pressed={gapOnly} onclick={() => (gapOnly = !gapOnly)} title="Exploited but no public Nuclei / Sigma / ET / YARA rule found">Detection gap</button>
    <span class="count muted num">{filtered.length} CVEs</span>
    <button class="btn small" onclick={exportCsv}>Export CSV</button>
  </div>
  <div class="scroll table-wrap">
    <table class="data">
      <thead>
        <tr>
          {#each cols as c (c.k)}
            <th class:num={c.num} aria-sort={ariaSort(c.k)} title={c.title}>
              <button onclick={() => sortBy(c.k)}>{c.label}{sortKey === c.k ? (desc ? ' ↓' : ' ↑') : ''}</button>
            </th>
          {/each}
          <th>Vendor · product</th>
          <th>Signals</th>
        </tr>
      </thead>
      <tbody>
        {#each sorted.slice(0, limit) as c (c.id)}
          <tr>
            <td><button class="chip mono" onclick={() => onFilter(q('cve', c.id))} title="Show stories about {c.id}">{c.id}</button></td>
            <td class="num">{c.cvss?.toFixed(1) ?? '—'}</td>
            <td class="num">{epssText(c.epss, c.epssPct)}</td>
            <td class="num">{deltaText(c.epssDelta) || '—'}</td>
            <td class="num">
              {#if c.kev}
                {@const due = daysUntil(c.kev.dueDate, now)}
                <span class="badge kev" title="Added {c.kev.dateAdded}, due {c.kev.dueDate}">{c.kev.dateAdded}</span>
                <div class="sub" class:overdue={due < 0}>{due < 0 ? `${-due}d overdue` : `due ${due}d`}</div>
              {:else}—{/if}
            </td>
            <td class="num">{c.sources}</td>
            <td class="num muted">{ago(c.lastSeen, now)}</td>
            <td class="prod" title={c.description}>{[c.vendor, c.product].filter(Boolean).join(' · ') || '—'}</td>
            <td class="sig">
              {#if c.kev?.ransomware}<span class="badge kev">Ransomware</span>{/if}
              {#if c.ssvc?.exploitation && c.ssvc.exploitation !== 'none'}<span class="badge warn">SSVC {c.ssvc.exploitation}</span>{/if}
              {#if c.ssvc?.automatable === 'yes'}<span class="badge">automatable</span>{/if}
              {#if c.poc}<span class="badge warn">PoC ×{c.poc.count}</span>{/if}
              {#if c.ransomware}<span class="badge kev" title={c.ransomware.groups.map((g) => g.name).join(', ') || 'CISA KEV: known ransomware use'}>Ransomware{c.ransomware.groups.length ? ` · ${c.ransomware.groups[0]!.name}${c.ransomware.groups.length > 1 ? ` +${c.ransomware.groups.length - 1}` : ''}` : ''}</span>{/if}
              {#if c.exploitation?.notInCisa}<span class="badge warn" title="Exploited per {c.exploitation.catalogs.join(', ')}">Exploited: {c.exploitation.catalogs.join('+')}</span>{/if}
              {#if c.exploitation?.honeypot7d}<span class="badge warn">Honeypot 7d</span>{/if}
              {#if c.detections && (c.detections.nuclei || c.detections.sigma.length || c.detections.et.length || c.detections.yara.length)}<span class="badge" title="Public detection content exists">Detections</span>{/if}
              {#if c.detectionGap}<span class="badge gap">Gap</span>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if sorted.length > limit}
      <div class="more"><button class="btn" onclick={() => (limit += 300)}>Show more ({sorted.length - limit} remaining)</button></div>
    {/if}
    {#if sorted.length === 0}<p class="muted empty">No CVEs match these filters.</p>{/if}
  </div>
</div>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
  }
  input[type='search'] {
    height: 28px;
    width: 240px;
    padding: 0 8px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--page);
  }
  .count {
    margin-left: auto;
    font-size: 12px;
  }
  .table-wrap {
    flex: 1;
    min-height: 0;
  }
  .sub {
    font-size: 11px;
    color: var(--muted);
  }
  .sub.overdue {
    color: var(--text);
    text-decoration: underline;
    text-decoration-color: var(--critical);
  }
  .prod {
    max-width: 260px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-2);
  }
  .sig {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .badge.gap {
    border-color: var(--warning);
    border-style: dashed;
    color: var(--text);
  }
  .more,
  .empty {
    padding: 14px;
    text-align: center;
  }
</style>
