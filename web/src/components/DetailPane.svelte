<script lang="ts">
  import type { ActorProfile, CveInfo, Story } from '../../../shared/types';
  import CveSignals from './CveSignals.svelte';
  import { actorCard, cveCard } from './EntityCards.svelte';
  import HoverCard from './HoverCard.svelte';
  import { GROUP_LABELS, PRIORITY_LABELS } from '../../../shared/types';
  import { copyText, daysUntil, deltaText, epssText, fmtDate, fmtDateTime, safeHref } from '../lib/format';
  import { prefs, term, toggleIn, type TermKind } from '../lib/prefs.svelte';
  import { q } from '../lib/query';
  import { toast } from '../lib/toast.svelte';

  interface Props {
    story: Story;
    cveInfo: Map<string, CveInfo>;
    actors: Map<string, ActorProfile>;
    now: number;
    onFilter: (token: string) => void;
    onActor: (name: string) => void;
    onGroup: (name: string) => void;
    onClose: () => void;
  }
  let { story, cveInfo, actors, now, onFilter, onActor, onGroup, onClose }: Props = $props();

  const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
  const countryLabel = (iso: string) => {
    try {
      return regionNames.of(iso) ?? iso;
    } catch {
      return iso;
    }
  };

  let copied = $state(false);
  const href = $derived(safeHref(story.url));
  const cves = $derived(story.cves.map((id) => cveInfo.get(id) ?? ({ id } as CveInfo)));
  const starred = $derived(prefs.starred.includes(story.id));
  const hidden = $derived(prefs.hidden.includes(story.id));

  async function copyCves() {
    copied = await copyText(story.cves.join('\n'));
    if (copied) toast(`Copied ${story.cves.length} CVE ID${story.cves.length === 1 ? '' : 's'}`, { timeout: 2500 });
    setTimeout(() => (copied = false), 1500);
  }

  function hideStory() {
    const id = story.id;
    toggleIn(prefs.hidden, id);
    if (prefs.hidden.includes(id)) toast('Story hidden', { action: { label: 'Undo', run: () => toggleIn(prefs.hidden, id) } });
  }

  const entityGroups = $derived(
    [
      { kind: 'actor' as const, label: 'Actors', values: story.actors },
      { kind: 'malware' as const, label: 'Malware', values: story.malware },
      { kind: 'vendor' as const, label: 'Vendors', values: story.vendors },
    ].filter((g) => g.values.length),
  );
  const countries = $derived(story.countries ?? []);

  const sevClass = (c: CveInfo) => ((c.cvss ?? 0) >= 9 ? 'crit' : (c.cvss ?? 0) >= 7 ? 'high' : '');
</script>

<article class="detail" aria-label="Story detail">
  <header>
    <div class="top">
      <span class="prio p{story.priority}">P{story.priority} · {PRIORITY_LABELS[story.priority]}</span>
      <div class="actions">
        <button class="icon-btn" aria-pressed={starred} title="Star (w)" aria-label="Star story" onclick={() => toggleIn(prefs.starred, story.id)}>★</button>
        <button class="icon-btn" aria-pressed={hidden} title="Hide story (m)" aria-label="Hide story" onclick={hideStory}>⊘</button>
        <button class="icon-btn close" title="Close (Esc)" aria-label="Close detail" onclick={onClose}>✕</button>
      </div>
    </div>
    <h2>
      {#if href}<a {href} target="_blank" rel="noopener noreferrer">{story.title} <span aria-hidden="true">↗</span></a>{:else}{story.title}{/if}
    </h2>
    <p class="byline">
      <span class="badge tier" title="Source tier">{story.tier}</span>
      {story.feed} · {GROUP_LABELS[story.group]} · first reported {fmtDateTime(story.date)}
      {#if story.lastSeen !== story.date}· latest {fmtDateTime(story.lastSeen)}{/if}
    </p>
    {#if story.reasons.length}
      <div class="reasons" aria-label="Why this priority">
        {#each story.reasons as r (r.code)}
          <span class="reason" class:r1={['kev-new', 'kev-ransom', 'ssvc-active', 'exploited-advisory'].includes(r.code)} class:r2={['kev', 'exploited-claim', 'epss-high', 'epss-jump', 'poc-new', 'multi-source', 'honeypot', 'exploited-multi', 'ransomware-linked', 'kev-ransom-flip'].includes(r.code)}>
            {r.label}{#if r.cve}&nbsp;<span class="muted">· {r.cve}</span>{/if}
          </span>
        {/each}
      </div>
    {/if}
  </header>

  {#if story.summary}<p class="summary">{story.summary}</p>{/if}

  {#if entityGroups.length || countries.length}
    <section>
      <h3>Entities</h3>
      {#each entityGroups as g (g.kind)}
        <div class="ent-row">
          <span class="ent-label">{g.label}</span>
          <div class="ents">
            {#each g.values as v (v)}
              {@render entity(g.kind, v)}
            {/each}
          </div>
        </div>
      {/each}
      {#if countries.length}
        <div class="ent-row">
          <span class="ent-label">Countries</span>
          <div class="ents">
            {#each countries as c (c)}<button class="chip" title="Filter stories naming {countryLabel(c)}" onclick={() => onFilter(`country:${c}`)}>{countryLabel(c)}</button>{/each}
          </div>
        </div>
      {/if}
    </section>
  {/if}

  {#if cves.length}
    <section>
      <div class="sec-head">
        <h3>CVEs <span class="muted num">({cves.length})</span></h3>
        <button class="btn small" onclick={copyCves}>{copied ? 'Copied' : 'Copy CVE list'}</button>
      </div>
      <ul class="cves">
        {#each cves.slice(0, 40) as c (c.id)}
          <li>
            <div class="cve-head">
              <HoverCard>
                <button class="chip mono" title="Filter stories by {c.id}" onclick={() => onFilter(q('cve', c.id))}>{c.id}</button>
                {#snippet card()}{@render cveCard(c.id, cveInfo.get(c.id))}{/snippet}
              </HoverCard>
              {#if c.kev}<span class="badge kev">KEV</span>{/if}
              {#if c.kev?.ransomware}<span class="badge kev">Ransomware</span>{/if}
              {#if c.cvss != null}<span class="badge sev {sevClass(c)} num" title="CVSS {c.cvssVersion} base score">CVSS {c.cvss.toFixed(1)}</span>{/if}
              <span class="badge num" title="EPSS: probability of exploitation activity in the next 30 days (percentile)">EPSS {epssText(c.epss, c.epssPct)}{#if c.epssDelta}&nbsp;{deltaText(c.epssDelta)}{/if}</span>
              {#if c.ssvc?.exploitation}<span class="badge" class:warn={c.ssvc.exploitation !== 'none'} title="CISA SSVC: Exploitation / Automatable / Technical impact">SSVC {c.ssvc.exploitation}{c.ssvc.automatable === 'yes' ? ' · automatable' : ''}{c.ssvc.technicalImpact === 'total' ? ' · total' : ''}</span>{/if}
              {#if c.poc}<span class="badge warn" title="Public proof-of-concept repositories on GitHub (first seen {fmtDate(c.poc.firstSeen)})">PoC ×{c.poc.count}</span>{/if}
              {@render watchBtn('cve', c.id)}
            </div>
            {#if c.vendor || c.product}<div class="cve-prod">{[c.vendor, c.product].filter(Boolean).join(' · ')}</div>{/if}
            <CveSignals info={c} {onGroup} />
            {#if c.kev}
              {@const due = daysUntil(c.kev.dueDate, now)}
              <div class="cve-kev">
                KEV added {fmtDate(c.kev.dateAdded)} · due {fmtDate(c.kev.dueDate)}
                {#if due >= -90}<b class:overdue={due < 0}>({due < 0 ? `${-due}d overdue` : due === 0 ? 'due today' : `${due}d left`})</b>{/if}
                — {c.kev.requiredAction}
              </div>
            {/if}
            {#if c.description}<p class="cve-desc">{c.description}</p>{/if}
            <div class="cve-links">
              <a href="https://www.cve.org/CVERecord?id={c.id}" target="_blank" rel="noopener noreferrer">cve.org ↗</a>
              <a href="https://nvd.nist.gov/vuln/detail/{c.id}" target="_blank" rel="noopener noreferrer">NVD ↗</a>
            </div>
          </li>
        {/each}
      </ul>
      {#if cves.length > 40}<p class="muted">… and {cves.length - 40} more (round-up item). Use “Copy CVE list” for all.</p>{/if}
    </section>
  {/if}

  <section>
    <h3>Sources <span class="muted num">({story.sources.length + 1})</span></h3>
    <ul class="sources">
      <li>
        <span class="badge tier">{story.tier}</span>
        <div>
          {#if href}<a {href} target="_blank" rel="noopener noreferrer">{story.title}</a>{:else}{story.title}{/if}
          <div class="muted">{story.feed} · {fmtDateTime(story.date)} · lead</div>
        </div>
      </li>
      {#each story.sources as src (src.url + src.feedId)}
        {@const sh = safeHref(src.url)}
        <li>
          <span class="badge tier">{src.tier}</span>
          <div>
            {#if sh}<a href={sh} target="_blank" rel="noopener noreferrer">{src.title}</a>{:else}{src.title}{/if}
            <div class="muted">{src.feed} · {fmtDateTime(src.date)}</div>
          </div>
        </li>
      {/each}
    </ul>
  </section>
</article>

{#snippet watchBtn(kind: TermKind, value: string)}
  {@const t = term(kind, value)}
  <button class="icon-btn" aria-pressed={prefs.watch.includes(t)} title={prefs.watch.includes(t) ? `Unwatch ${value}` : `Watch ${value}`} aria-label="Watch {value}" onclick={() => toggleIn(prefs.watch, t)}>☆</button>
{/snippet}

{#snippet entity(kind: 'actor' | 'malware' | 'vendor', value: string)}
  {@const t = term(kind, value)}
  <span class="ent">
    {#if kind === 'actor'}
      <HoverCard>
        <button class="chip actor" title="Open {value} profile" onclick={() => onActor(value)}>{value} →</button>
        {#snippet card()}{@render actorCard(value, actors.get(value))}{/snippet}
      </HoverCard>
    {:else}
      <button class="chip" title="Filter by {kind} {value}" onclick={() => onFilter(q(kind, value))}>{value}</button>
    {/if}
    <button class="icon-btn" aria-pressed={prefs.watch.includes(t)} title={prefs.watch.includes(t) ? 'Unwatch' : 'Watch'} aria-label="Watch {value}" onclick={() => toggleIn(prefs.watch, t)}>☆</button>
    <button class="icon-btn" aria-pressed={prefs.mute.includes(t)} title={prefs.mute.includes(t) ? 'Unmute' : 'Mute: hide stories about this'} aria-label="Mute {value}" onclick={() => toggleIn(prefs.mute, t)}>⊘</button>
  </span>
{/snippet}

<style>
  .detail {
    padding: 14px 16px 24px;
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .actions {
    display: flex;
    gap: 2px;
  }
  h2 {
    margin: 10px 0 6px;
    font-size: 16px;
    line-height: 1.35;
    font-weight: 600;
  }
  .byline {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    color: var(--muted);
    font-size: 12px;
  }
  .reasons {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 10px;
  }
  .summary {
    margin: 12px 0 0;
    color: var(--text-2);
  }
  section {
    margin-top: 18px;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-2);
  }
  .sec-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .sec-head h3 {
    margin: 0;
  }
  .ent-row {
    display: grid;
    grid-template-columns: 64px 1fr;
    gap: 8px;
    margin-bottom: 6px;
  }
  .ent-label {
    color: var(--muted);
    font-size: 12px;
    padding-top: 2px;
  }
  .ents {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 8px;
  }
  .ent {
    display: inline-flex;
    align-items: center;
  }
  .cves,
  .sources {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .cves li {
    padding: 8px 0;
    border-top: 1px solid var(--border);
  }
  .cve-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
  }
  .badge.sev.high {
    border-color: var(--serious);
  }
  .badge.sev.crit {
    border-color: var(--critical);
    color: var(--text);
  }
  .cve-prod {
    margin-top: 4px;
    color: var(--text-2);
    font-size: 12px;
  }
  .cve-kev {
    margin-top: 4px;
    font-size: 12px;
    color: var(--text-2);
  }
  .cve-kev b {
    font-weight: 600;
    color: var(--text);
  }
  .cve-kev b.overdue {
    text-decoration: underline;
    text-decoration-color: var(--critical);
    text-decoration-thickness: 2px;
  }
  .cve-desc {
    margin: 6px 0 0;
    font-size: 12px;
    color: var(--muted);
    display: -webkit-box;
    -webkit-line-clamp: 4;
    line-clamp: 4;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .cve-links {
    display: flex;
    gap: 12px;
    margin-top: 4px;
    font-size: 11.5px;
    color: var(--accent-ink);
  }
  .sources li {
    display: grid;
    grid-template-columns: 22px 1fr;
    gap: 8px;
    padding: 6px 0;
    border-top: 1px solid var(--border);
  }
  .sources .muted {
    font-size: 11.5px;
  }
</style>
