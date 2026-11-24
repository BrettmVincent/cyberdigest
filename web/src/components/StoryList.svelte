<script lang="ts">
  import type { ActorProfile, CveInfo, Story } from '../../../shared/types';
  import { PRIORITY_LABELS } from '../../../shared/types';
  import { ago, epssText, safeHref } from '../lib/format';
  import type { ListRow } from '../lib/rows';
  import { actorCard, cveCard } from './EntityCards.svelte';
  import HoverCard from './HoverCard.svelte';

  interface Props {
    rows: ListRow[];
    total: number;
    /** false = every-article mode (one row per article). */
    grouped: boolean;
    selectedKey: string | null;
    selectedStoryId: string | null;
    now: number;
    cveInfo: Map<string, CveInfo>;
    actors: Map<string, ActorProfile>;
    isNew: (s: Story) => boolean;
    isWatched: (s: Story) => boolean;
    isStarred: (s: Story) => boolean;
    isArrived: (s: Story) => boolean;
    onSelect: (id: string) => void;
    onOpen: (id: string) => void;
    onActor: (name: string) => void;
    onMore: () => void;
  }
  let { rows, total, grouped, selectedKey, selectedStoryId, now, cveInfo, actors, isNew, isWatched, isStarred, isArrived, onSelect, onOpen, onActor, onMore }: Props = $props();

  function topEpss(s: Story): CveInfo | undefined {
    let best: CveInfo | undefined;
    for (const c of s.cves) {
      const i = cveInfo.get(c);
      if (i?.epss != null && (!best || i.epss > best.epss!)) best = i;
    }
    return best;
  }

  // Count KEV entries from the last year only; old ones (e.g. a Log4Shell mention) show as a reason chip instead.
  const kevCount = (s: Story) =>
    s.cves.filter((c) => {
      const k = cveInfo.get(c)?.kev;
      return k && now - Date.parse(k.dateAdded) <= 365 * 86_400_000;
    }).length;
</script>

<ul class="list" role="listbox" aria-label={grouped ? 'Stories' : 'Articles'} aria-activedescendant={selectedKey ? `row-${selectedKey}` : undefined} tabindex="-1">
  {#each rows as row (row.key)}
    {@const s = row.story}
    {@const epss = topEpss(s)}
    {@const kev = kevCount(s)}
    {@const href = safeHref(row.url)}
    <li
      id="row-{row.key}"
      class="row"
      class:selected={row.key === selectedKey}
      class:sibling={!grouped && row.key !== selectedKey && s.id === selectedStoryId}
      class:watched={isWatched(s)}
      class:arrived={isArrived(s)}
      role="option"
      aria-selected={row.key === selectedKey}
      onclick={() => onSelect(row.key)}
      ondblclick={() => onOpen(row.key)}
      onkeydown={(e) => e.key === 'Enter' && onOpen(row.key)}
    >
      <span class="prio p{s.priority}" title="Priority {s.priority}: {PRIORITY_LABELS[s.priority]}{grouped ? '' : ' (of the story this article belongs to)'}">P{s.priority}</span>
      <div class="main">
        <div class="title">
          {#if isNew(s)}<span class="new" title="New since your last visit"><span class="sr-only">New: </span></span>{/if}
          {#if isStarred(s)}<span class="star" title="Starred" aria-label="Starred">★</span>{/if}
          <span class="t">{row.title}</span>
        </div>
        <div class="meta">
          <span class="feed">{row.feed}</span>
          {#if grouped}
            {#if s.sourceCount > 1}<span class="srcs" title="{s.sourceCount} sources cover this story">+{s.sourceCount - 1}</span>{/if}
          {:else if row.count > 1}
            <span class="dup" title="This story has {row.count} articles; select to see the grouped story">{row.index === 0 ? 'lead' : 'duplicate'} · {row.index + 1} of {row.count}</span>
          {/if}
          {#if kev}<span class="badge kev" title="{kev} CVE(s) in CISA KEV">KEV{kev > 1 ? ` ×${kev}` : ''}</span>{/if}
          {#if epss}<span class="badge" title="Highest EPSS among this story's CVEs ({epss.id})">EPSS {epssText(epss.epss, epss.epssPct)}</span>{/if}
          {#each s.reasons.filter((r) => !r.code.startsWith('kev') && r.code !== 'epss-high').slice(0, 3) as r (r.code)}
            <span class="reason" class:r1={['ssvc-active', 'exploited-advisory'].includes(r.code)} class:r2={['exploited-claim', 'epss-jump', 'poc-new', 'multi-source', 'honeypot', 'exploited-multi', 'ransomware-linked', 'kev-ransom-flip'].includes(r.code)}>{r.label}</span>
          {/each}
          {#each s.cves.slice(0, 2) as c (c)}
            <HoverCard>
              <span class="chip mono">{c}</span>
              {#snippet card()}{@render cveCard(c, cveInfo.get(c))}{/snippet}
            </HoverCard>
          {/each}
          {#if s.cves.length > 2}<span class="more">+{s.cves.length - 2} CVEs</span>{/if}
          {#each s.actors.slice(0, 2) as a (a)}
            <HoverCard>
              <button class="chip actor" onclick={(e) => (e.stopPropagation(), onActor(a))}>{a}</button>
              {#snippet card()}{@render actorCard(a, actors.get(a))}{/snippet}
            </HoverCard>
          {/each}
          {#each s.malware.slice(0, Math.max(0, 2 - s.actors.length)) as m (m)}<span class="chip">{m}</span>{/each}
        </div>
      </div>
      <div class="side">
        <time class="age num" datetime={row.date} title="{grouped ? 'Last activity' : 'Published'} {new Date(row.date).toLocaleString()}">{ago(row.date, now)}</time>
        {#if href}
          <a class="icon-btn" {href} target="_blank" rel="noopener noreferrer" title="Open original ({row.feed})" aria-label="Open original article" onclick={(e) => e.stopPropagation()}>↗</a>
        {/if}
      </div>
    </li>
  {/each}
</ul>
{#if rows.length < total}
  <div class="more-wrap">
    <button class="btn" onclick={onMore}>Show more ({total - rows.length} remaining)</button>
  </div>
{/if}

<style>
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .row {
    display: grid;
    grid-template-columns: 44px minmax(0, 1fr) auto;
    gap: 10px;
    align-items: start;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    position: relative;
  }
  .row:hover {
    background: var(--surface-2);
  }
  .row.selected {
    background: var(--accent-wash);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  /* Every-article mode: other articles of the selected story. */
  .row.sibling {
    box-shadow: inset 3px 0 0 var(--border-strong);
  }
  .dup {
    font-size: 11px;
    color: var(--muted);
    border: 1px dashed var(--border-strong);
    border-radius: 3px;
    padding: 0 5px;
  }
  /* Stories that appeared during this session's auto-refresh get a brief highlight. */
  .row.arrived {
    animation: arrive 2.4s ease-out;
  }
  @keyframes arrive {
    from {
      background: var(--accent-wash);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .row.arrived {
      animation: none;
      background: var(--accent-wash);
    }
  }
  .chip.actor:hover {
    border-color: var(--accent);
  }
  .row.watched .t {
    text-decoration: underline;
    text-decoration-color: var(--accent);
    text-underline-offset: 3px;
  }
  .prio {
    margin-top: 1px;
  }
  .title {
    display: flex;
    align-items: baseline;
    gap: 6px;
    font-size: 13.5px;
    font-weight: 500;
    color: var(--text);
  }
  .t {
    overflow: hidden;
    text-overflow: ellipsis;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
  }
  .new {
    flex: none;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--new-dot);
    transform: translateY(-1px);
  }
  .star {
    color: var(--accent-ink);
    font-size: 12px;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
    margin-top: 4px;
    font-size: 12px;
    color: var(--muted);
  }
  .feed {
    color: var(--text-2);
  }
  .srcs {
    color: var(--text-2);
    font-weight: 600;
  }
  .more {
    font-size: 11px;
  }
  .side {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .age {
    color: var(--muted);
    font-size: 12px;
    min-width: 26px;
    text-align: right;
  }
  .more-wrap {
    padding: 14px;
    text-align: center;
  }
</style>
