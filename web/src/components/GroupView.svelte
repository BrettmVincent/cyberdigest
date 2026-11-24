<script lang="ts">
  // Ransomware group profile, laid out like a CISA #StopRansomware advisory:
  // behaviour (activity, CVEs exploited, tools), not victims.
  import type { RansomGroupProfile } from '../../../shared/types';
  import { fmtDate } from '../lib/format';
  import { ROLE_LABEL, rvmUrl } from '../lib/links';
  import { prefs, term, toggleIn } from '../lib/prefs.svelte';
  import { q } from '../lib/query';
  import ChartCard from './charts/ChartCard.svelte';
  import Sparkline from './Sparkline.svelte';

  interface Props {
    group: RansomGroupProfile;
    weeks: string[];
    caveat: string;
    rvmUpdated: string | null;
    onBack: () => void;
    onFilter: (token: string) => void;
  }
  let { group, weeks, caveat, rvmUpdated, onBack, onFilter }: Props = $props();

  const watchTerm = $derived(term('malware', group.name));
  const watching = $derived(prefs.watch.includes(watchTerm));
  const toolsByCat = $derived.by(() => {
    const m = new Map<string, string[]>();
    for (const t of group.tools) m.set(t.category, [...(m.get(t.category) ?? []), t.name]);
    return [...m.entries()].map(([category, tools]) => ({ category, tools: tools.sort() }));
  });
  const usd = (n: number) => new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(n);
</script>

<div class="scroll gv">
  <header class="head">
    <button class="btn small" onclick={onBack}>← Back</button>
    <div class="title">
      <h1>{group.name}</h1>
      <div class="facts">
        <span class="badge">Ransomware group</span>
        <span class="muted">{group.last7} leak-site posts this week · {group.last30} in 30 days</span>
      </div>
    </div>
    <div class="head-actions">
      <button class="btn small" aria-pressed={watching} onclick={() => toggleIn(prefs.watch, watchTerm)}>{watching ? '★ Watching' : '☆ Watch'}</button>
      <button class="btn small" onclick={() => onFilter(q('malware', group.name))}>Stories</button>
    </div>
  </header>

  {#if group.aliases.length}
    <p class="aliases"><span class="muted">Also tracked as</span> {#each group.aliases as a (a)}<span class="chip">{a}</span>{/each}</p>
  {/if}
  {#if group.description}<p class="desc">{group.description}</p>{/if}

  <div class="grid">
    <div class="col">
      <ChartCard title="Activity" subtitle="Leak-site posts per week, 12 weeks">
        <div class="activity">
          <Sparkline values={group.weekly} days={weeks} baseline={null} label="{group.name} (RansomLook)" width={280} height={52} />
          {#if group.weeklyRl}<Sparkline values={group.weeklyRl} days={weeks} baseline={null} label="{group.name} (Ransomware.live)" width={280} height={52} />{/if}
        </div>
        <p class="note">{caveat}</p>
        <p class="credit">Source: RansomLook.io (CC BY 4.0){group.weeklyRl ? ' · Ransomware.live (second line)' : ''}</p>
      </ChartCard>

      <ChartCard title="Context" subtitle="Counts only: content is linked, never reproduced">
        <dl class="counts">
          <dt>Ransom note samples</dt><dd class="num">{group.notes || '—'}</dd>
          <dt>Negotiation chats</dt><dd class="num">{group.chats || '—'}</dd>
          <dt>Ransom payments traced</dt>
          <dd class="num">
            {#if group.payments}{group.payments.count} txns · {usd(group.payments.usd)}{#if group.payments.last} · last {fmtDate(group.payments.last)}{/if}{:else}—{/if}
          </dd>
        </dl>
        <p class="credit">Notes: Zscaler ThreatLabz (MIT) · Chats: Ransomchats by Valéry Rieß-Marchive (MIT) · Payments: Ransomwhere, CC BY 4.0, doi:10.5281/zenodo.6512122</p>
      </ChartCard>

      <ChartCard title="Investigate further" subtitle="External resources">
        <ul class="links">
          {#each group.links as l (l.url)}<li><a href={l.url} target="_blank" rel="noopener noreferrer">{l.label} ↗</a></li>{/each}
        </ul>
      </ChartCard>
    </div>

    <div class="col">
      <ChartCard title="Vulnerabilities exploited" subtitle="Ransomware Vulnerability Matrix · updated {fmtDate(rvmUpdated ?? undefined) || 'n/a'} · patch these first if you run the product">
        {#if group.cves.length === 0}
          <p class="muted">None recorded in the matrix: that means 'not recorded', not 'not used'.</p>
        {:else}
          <table class="data">
            <thead><tr><th>CVE</th><th>Product</th><th>Role</th><th>Sources</th></tr></thead>
            <tbody>
              {#each group.cves as c (c.id)}
                <tr>
                  <td><button class="chip mono" onclick={() => onFilter(q('cve', c.id))}>{c.id}</button></td>
                  <td class="text-2">{c.vendor ? `${c.vendor} · ` : ''}{c.product}</td>
                  <td class="muted">{ROLE_LABEL[c.role] || 'operator'}</td>
                  <td>{#each c.sources as s, i (s)}<a href={s} target="_blank" rel="noopener noreferrer">[{i + 1}]</a>{' '}{/each}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        <p class="credit">By Will Thomas (BushidoUK), CC BY 4.0, parsed and normalised by CyberDigest · <a href={rvmUrl} target="_blank" rel="noopener noreferrer">source ↗</a></p>
      </ChartCard>

      <ChartCard title="Tools observed" subtitle="Ransomware Tool Matrix · hunt for these; many are legitimate IT tools">
        {#if toolsByCat.length === 0}
          <p class="muted">No tools recorded for this group.</p>
        {:else}
          <div class="tools">
            {#each toolsByCat as c (c.category)}
              <section><h3>{c.category}</h3><p>{c.tools.join(', ')}</p></section>
            {/each}
          </div>
        {/if}
        <p class="credit">Ransomware Tool Matrix by Will Thomas (BushidoUK), CC BY 4.0</p>
      </ChartCard>
    </div>
  </div>
</div>

<style>
  .gv {
    height: 100%;
    padding: 16px 20px 40px;
    background: var(--page);
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: 14px;
  }
  .title {
    flex: 1;
  }
  h1 {
    margin: 0;
    font-size: 22px;
  }
  .facts {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-top: 6px;
    font-size: 12px;
  }
  .head-actions {
    display: flex;
    gap: 6px;
  }
  .aliases {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
    margin: 14px 0 0;
    font-size: 12px;
  }
  .desc {
    max-width: 100ch;
    margin: 12px 0 0;
    color: var(--text-2);
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr);
    gap: 12px;
    margin-top: 16px;
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 12px;
    min-width: 0;
  }
  .activity {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .note {
    margin: 8px 0 0;
    font-size: 11.5px;
    color: var(--muted);
  }
  .credit {
    margin: 8px 0 0;
    font-size: 11px;
    color: var(--muted);
  }
  .credit a,
  td a,
  .links a {
    color: var(--accent-ink);
  }
  .counts {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 6px 12px;
    margin: 0;
    font-size: 12.5px;
  }
  .counts dd {
    margin: 0;
    text-align: right;
  }
  .links {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 12.5px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 11.5px;
  }
  .tools {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .tools h3 {
    margin: 0;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  .tools p {
    margin: 2px 0 0;
    font-size: 12.5px;
  }
  @media (max-width: 1100px) {
    .grid {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
