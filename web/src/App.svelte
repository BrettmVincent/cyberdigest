<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import { fade } from 'svelte/transition';
  import type { ActorProfile, CveInfo, Priority, Story } from '../../shared/types';
  import { PRIORITY_LABELS } from '../../shared/types';
  import ActorView from './components/ActorView.svelte';
  import CommandPalette, { type Command } from './components/CommandPalette.svelte';
  import CveTable from './components/CveTable.svelte';
  import GroupView from './components/GroupView.svelte';
  import Overview from './components/Overview.svelte';
  import RansomwareView from './components/RansomwareView.svelte';
  import Toasts from './components/Toasts.svelte';
  import { reducedMotion } from './lib/actions';
  import { articleRows, groupedRows, storyIdOf, type ListRow } from './lib/rows';
  import { toast } from './lib/toast.svelte';
  import DetailPane from './components/DetailPane.svelte';
  import EpssPanel from './components/EpssPanel.svelte';
  import HealthPanel from './components/HealthPanel.svelte';
  import HelpDialog from './components/HelpDialog.svelte';
  import KevPanel from './components/KevPanel.svelte';
  import MultiSourcePanel from './components/MultiSourcePanel.svelte';
  import SourcesView from './components/SourcesView.svelte';
  import StoryList from './components/StoryList.svelte';
  import TrendsPanel from './components/TrendsPanel.svelte';
  import WatchlistDialog from './components/WatchlistDialog.svelte';
  import WatchPanel from './components/WatchPanel.svelte';
  import { fetchMeta, loadDataset, type Dataset } from './lib/data';
  import { ago, download, fmtDateTime, safeHref, toCsv } from './lib/format';
  import { prefs, previousVisit, savePrefs, toggleIn, type View } from './lib/prefs.svelte';
  import { matchStory, parseQuery, q as tokenFor, QUERY_HELP, termMatches } from './lib/query';

  const VIEWS: View[] = ['overview', 'stories', 'cves', 'sources', 'ransomware', 'actor', 'group'];
  const motion = reducedMotion() ? 0 : 140;
  const REFRESH_MS = 5 * 60_000;
  const PAGE = 150;

  let data = $state<Dataset | null>(null);
  let error = $state<string | null>(null);
  let now = $state(Date.now());

  // UI state (mirrored into the URL hash so views can be shared).
  let query = $state('');
  let bands = $state<Priority[]>([1, 2, 3]);
  let view = $state<View>('overview');
  let actorName = $state<string | null>(null);
  let groupId = $state<string | null>(null);
  /** Selected list row: a story id (grouped) or "storyId~n" (every-article mode). */
  let selectedKey = $state<string | null>(null);
  const selectedId = $derived(selectedKey ? storyIdOf(selectedKey) : null);
  /** Story ids that appeared during this session's auto-refreshes (briefly highlighted). */
  let arrived = $state<Set<string>>(new Set());
  let palette = $state<CommandPalette | undefined>();
  let detailOpen = $state(false);
  let railOpen = $state(false);
  let limit = $state(PAGE);
  let searchFocused = $state(false);

  let searchEl = $state<HTMLInputElement | undefined>();
  let watchDialog = $state<WatchlistDialog | undefined>();
  let helpDialog = $state<HelpDialog | undefined>();

  // ── Derived data ────────────────────────────────────────────────
  const cveInfo = $derived(new Map<string, CveInfo>((data?.cves ?? []).map((c) => [c.id, c])));
  const actors = $derived(new Map<string, ActorProfile>((data?.actors ?? []).map((a) => [a.name, a])));
  const storyById = $derived(new Map<string, Story>((data?.stories ?? []).map((s) => [s.id, s])));
  const currentActor = $derived(actorName ? actors.get(actorName) : undefined);
  const currentGroup = $derived(groupId ? data?.ransomware.groups.find((g) => g.id === groupId) : undefined);
  const gkey = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  const parsed = $derived(parseQuery(query));

  const isWatched = (s: Story) => prefs.watch.some((t) => termMatches(t, s));
  const isStarred = (s: Story) => prefs.starred.includes(s.id);
  const isNew = (s: Story) => previousVisit !== null && s.firstSeen > previousVisit;
  const isMuted = (s: Story) => prefs.hidden.includes(s.id) || (prefs.mute.some((t) => termMatches(t, s)) && !isWatched(s));

  const unmuted = $derived((data?.stories ?? []).filter((s) => !isMuted(s)));
  const mutedCount = $derived((data?.stories.length ?? 0) - unmuted.length);
  const ctx = $derived({ now, cveInfo, actors, isWatched, isStarred, isNew });
  const matched = $derived(unmuted.filter((s) => matchStory(s, parsed, ctx)));
  const grouped = $derived(prefs.grouped);
  const articleCount = (s: Story) => s.sources.length + 1;
  const bandCounts = $derived(
    ([1, 2, 3, 4] as Priority[]).map((p) => matched.filter((s) => s.priority === p).reduce((n, s) => n + (grouped ? 1 : articleCount(s)), 0)),
  );
  const visible = $derived.by(() => {
    const list = parsed.priority.length ? matched : matched.filter((s) => bands.includes(s.priority));
    // Stable: pipeline order within a band, but watched/starred stories float to the top of their band.
    return list
      .map((s, i) => ({ s, i, w: isWatched(s) || isStarred(s) ? 0 : 1 }))
      .sort((a, b) => a.s.priority - b.s.priority || a.w - b.w || a.i - b.i)
      .map((x) => x.s);
  });
  const rows = $derived<ListRow[]>(grouped ? groupedRows(visible) : articleRows(visible));
  const selected = $derived(selectedId ? (storyById.get(selectedId) ?? null) : null);

  /** Select by story id or row key, normalised to the current list mode. */
  function setSelection(idOrKey: string | null) {
    if (!idOrKey) {
      selectedKey = null;
      return;
    }
    const id = storyIdOf(idOrKey);
    selectedKey = grouped ? id : idOrKey.includes('~') ? idOrKey : `${id}~0`;
  }

  // Switching grouping keeps the same story selected.
  $effect(() => {
    void grouped;
    untrack(() => setSelection(selectedKey));
  });
  const watchHits = $derived(prefs.watch.length ? unmuted.filter(isWatched) : []);
  const newCounts = $derived.by(() => {
    if (!previousVisit) return null;
    const fresh = unmuted.filter(isNew);
    return { total: fresh.length, p1: fresh.filter((s) => s.priority === 1).length, p2: fresh.filter((s) => s.priority === 2).length };
  });

  const ageMin = $derived(data ? (now - Date.parse(data.meta.generatedAt)) / 60_000 : 0);
  const freshness = $derived(ageMin >= 90 ? 'very-stale' : ageMin >= 45 ? 'stale' : 'fresh');

  // ── Effects ─────────────────────────────────────────────────────
  $effect(() => {
    document.documentElement.dataset.theme = prefs.theme;
  });

  $effect(() => {
    // Persist any preference change.
    JSON.stringify(prefs);
    savePrefs();
  });

  $effect(() => {
    const params = new URLSearchParams();
    if (query.trim()) params.set('q', query.trim());
    if (bands.join('') !== '123') params.set('b', bands.join(''));
    params.set('v', view);
    if (view === 'actor' && actorName) params.set('a', actorName);
    if (view === 'group' && groupId) params.set('g', groupId);
    if (selectedId && view === 'stories') params.set('s', selectedId);
    if (!grouped && view === 'stories') params.set('d', '0');
    const hash = params.toString();
    if (location.hash.slice(1) !== hash) history.replaceState(null, '', hash ? `#${hash}` : location.pathname + location.search);
  });

  // The last main view becomes the landing view next time.
  $effect(() => {
    if (view !== 'actor' && view !== 'group') prefs.view = view;
  });

  // Reset paging when the filter changes.
  $effect(() => {
    void query;
    void bands;
    limit = PAGE;
  });

  function readHash() {
    const p = new URLSearchParams(location.hash.slice(1));
    query = p.get('q') ?? '';
    const b = (p.get('b') ?? '123').split('').map(Number).filter((n) => n >= 1 && n <= 4) as Priority[];
    bands = b.length ? b : [1, 2, 3];
    const v = p.get('v') as View | null;
    view = v && VIEWS.includes(v) ? v : location.hash.length > 1 ? 'stories' : prefs.view;
    actorName = p.get('a');
    groupId = p.get('g');
    if (view === 'actor' && !actorName) view = 'overview';
    if (view === 'group' && !groupId) view = 'ransomware';
    if (p.get('d') === '0') prefs.grouped = false;
    setSelection(p.get('s'));
  }

  async function refresh(force = false) {
    try {
      const meta = await fetchMeta();
      if (!force && data && meta.generatedAt === data.meta.generatedAt) return;
      const before = data ? new Set(data.stories.map((s) => s.id)) : null;
      data = await loadDataset(meta);
      error = null;
      if (before) {
        const fresh = data.stories.filter((s) => !before.has(s.id));
        if (fresh.length) {
          arrived = new Set([...arrived, ...fresh.map((s) => s.id)]);
          const p1 = fresh.filter((s) => s.priority === 1);
          if (p1.length) {
            toast(p1.length === 1 ? `New P1: ${p1[0]!.title}` : `${p1.length} new P1 stories`, {
              tone: 'alert',
              timeout: 15000,
              action: { label: 'View', run: () => (p1.length === 1 ? openStory(p1[0]!.id) : addFilter('p:1 is:new')) },
            });
          } else {
            toast(`${fresh.length} new ${fresh.length === 1 ? 'story' : 'stories'} (no P1)`, { timeout: 4000 });
          }
        }
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  // Read shared-link state before the hash-sync effect first runs.
  readHash();

  onMount(() => {
    void refresh(true);
    const clock = setInterval(() => (now = Date.now()), 30_000);
    const poll = setInterval(() => void refresh(), REFRESH_MS);
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        now = Date.now();
        void refresh();
      } else {
        prefs.lastVisit = new Date().toISOString();
        savePrefs();
      }
    };
    const onHide = () => {
      prefs.lastVisit = new Date().toISOString();
      savePrefs();
    };
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', onHide);
    window.addEventListener('hashchange', readHash);
    return () => {
      clearInterval(clock);
      clearInterval(poll);
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', onHide);
      window.removeEventListener('hashchange', readHash);
    };
  });

  // ── Actions ─────────────────────────────────────────────────────
  function addFilter(token: string) {
    const existing = query.trim();
    query = existing.includes(token) ? existing : `${existing} ${token}`.trim();
    view = 'stories';
    railOpen = false;
  }

  let backView: View = 'overview';
  function openActor(name: string) {
    if (view !== 'actor' && view !== 'group') backView = view;
    actorName = name;
    view = 'actor';
    railOpen = false;
  }

  /** Open a ransomware group profile by id, display name or alias. */
  function openGroup(nameOrId: string) {
    const k = gkey(nameOrId);
    const g = data?.ransomware.groups.find((x) => x.id === nameOrId || gkey(x.name) === k || x.aliases.some((a) => gkey(a) === k));
    if (!g) {
      toast(`No ransomware profile for “${nameOrId}”`, { timeout: 3000 });
      return;
    }
    if (view !== 'actor' && view !== 'group') backView = view;
    groupId = g.id;
    view = 'group';
    railOpen = false;
  }

  function openStory(id: string) {
    const s = storyById.get(id);
    if (s && !bands.includes(s.priority) && !parsed.priority.length) bands = [...bands, s.priority].sort();
    view = 'stories';
    void select(id, true);
  }

  function hideSelected(sel: Story) {
    // Next row belonging to a different story (in every-article mode a story spans several rows).
    const i = rows.findIndex((r) => r.key === selectedKey);
    const next = rows.slice(i + 1).find((r) => r.story.id !== sel.id) ?? rows.slice(0, Math.max(0, i)).reverse().find((r) => r.story.id !== sel.id);
    toggleIn(prefs.hidden, sel.id);
    setSelection(next?.key ?? null);
    if (prefs.hidden.includes(sel.id)) toast('Story hidden', { action: { label: 'Undo', run: () => toggleIn(prefs.hidden, sel.id) } });
  }

  function words(s: string): string[] {
    return s.toLowerCase().split(/\s+/).filter(Boolean);
  }
  const hasAll = (hay: string, ws: string[]) => ws.every((w) => hay.includes(w));

  /** Command-palette results: actions, then CVEs, actors, vendors and stories matching the input. */
  function commands(input: string): Command[] {
    const ws = words(input);
    const out: Command[] = [];
    const actions: Command[] = [
      { id: 'go-overview', group: 'Go to', label: 'Overview', hint: '1', run: () => (view = 'overview') },
      { id: 'go-stories', group: 'Go to', label: 'Stories', hint: '2', run: () => (view = 'stories') },
      { id: 'go-cves', group: 'Go to', label: 'CVEs', hint: '3', run: () => (view = 'cves') },
      { id: 'go-sources', group: 'Go to', label: 'Sources, credits & pipeline health', hint: '4', run: () => (view = 'sources') },
      { id: 'go-ransomware', group: 'Go to', label: 'Ransomware', hint: '5', run: () => (view = 'ransomware') },
      { id: 'act-rw', group: 'Actions', label: 'Show stories about ransomware-linked CVEs', run: () => addFilter('ransomware:yes') },
      { id: 'act-gap', group: 'Actions', label: 'Show exploited CVEs with no public detection', run: () => addFilter('gap:yes') },
      { id: 'act-new', group: 'Actions', label: 'Show stories new since my last visit', run: () => addFilter('is:new') },
      { id: 'act-p1', group: 'Actions', label: 'Show P1 stories from the last 7 days', run: () => addFilter('p:1 since:7d') },
      { id: 'act-kev', group: 'Actions', label: 'Show stories with KEV CVEs', run: () => addFilter('kev:yes') },
      { id: 'act-watch', group: 'Actions', label: 'Manage watchlist & mutes', run: () => watchDialog?.open() },
      {
        id: 'act-dedupe',
        group: 'Actions',
        label: grouped ? 'Turn deduplication off (show every article)' : 'Turn deduplication on (group into stories)',
        hint: 'd',
        run: () => ((view = 'stories'), toggleGrouping()),
      },
      { id: 'act-p4', group: 'Actions', label: bands.includes(4) ? 'Hide P4 context stories' : 'Show P4 context stories', hint: 'p', run: () => toggleBand(4) },
      { id: 'act-theme', group: 'Actions', label: `Switch to ${prefs.theme === 'dark' ? 'light' : 'dark'} theme`, hint: 't', run: () => (prefs.theme = prefs.theme === 'dark' ? 'light' : 'dark') },
      { id: 'act-clear', group: 'Actions', label: 'Clear search', run: () => (query = '') },
      { id: 'act-help', group: 'Actions', label: 'Priority rules & keyboard shortcuts', hint: '?', run: () => helpDialog?.open() },
    ];
    out.push(...actions.filter((c) => hasAll(c.label.toLowerCase(), ws)));
    if (!data || ws.length === 0) return out;

    const text = input.trim();
    const cveQ = text.toLowerCase().replace(/^cve-?/, '');
    if (/^\d{4}/.test(cveQ)) {
      for (const c of data.cves.filter((c) => c.id.toLowerCase().slice(4).startsWith(cveQ)).slice(0, 6)) {
        out.push({ id: `cve-${c.id}`, group: 'CVEs', label: c.id, hint: [c.vendor, c.product].filter(Boolean).join(' · ') || undefined, run: () => addFilter(tokenFor('cve', c.id)) });
      }
    }
    for (const a of data.actors.filter((a) => hasAll([a.name, ...a.aliases].join(' ').toLowerCase(), ws)).slice(0, 5)) {
      out.push({ id: `actor-${a.name}`, group: 'Threat actors', label: a.name, hint: a.countryName ?? undefined, run: () => openActor(a.name) });
    }
    for (const g of data.ransomware.groups.filter((g) => hasAll([g.name, ...g.aliases].join(' ').toLowerCase(), ws)).slice(0, 5)) {
      out.push({ id: `group-${g.id}`, group: 'Ransomware groups', label: g.name, hint: g.last30 ? `${g.last30} posts / 30d` : `${g.cves.length} CVEs`, run: () => openGroup(g.id) });
    }
    const vendors = [...new Set(data.stories.flatMap((s) => s.vendors))].filter((v) => hasAll(v.toLowerCase(), ws)).slice(0, 4);
    for (const v of vendors) out.push({ id: `vendor-${v}`, group: 'Vendors', label: v, hint: 'filter stories', run: () => addFilter(tokenFor('vendor', v)) });
    for (const s of data.stories.filter((s) => hasAll(`${s.title} ${s.cves.join(' ')}`.toLowerCase(), ws)).slice(0, 8)) {
      out.push({ id: `story-${s.id}`, group: 'Stories', label: s.title, hint: `P${s.priority} · ${s.feed}`, run: () => openStory(s.id) });
    }
    out.push({ id: 'search', group: 'Search', label: `Search stories for “${text}”`, run: () => ((query = text), (view = 'stories')) });
    return out;
  }

  async function select(idOrKey: string, open = false) {
    setSelection(idOrKey);
    if (open) detailOpen = true;
    await tick();
    document.getElementById(`row-${selectedKey}`)?.scrollIntoView({ block: 'nearest' });
  }

  function move(delta: number) {
    if (!rows.length) return;
    const i = rows.findIndex((r) => r.key === selectedKey);
    const next = i < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, i + delta));
    if (next >= limit) limit += PAGE;
    void select(rows[next]!.key);
  }

  function toggleGrouping() {
    prefs.grouped = !prefs.grouped;
    limit = PAGE;
    toast(prefs.grouped ? 'Grouping on: duplicate coverage collapsed into stories' : 'Grouping off: showing every article', { timeout: 2500 });
  }

  function toggleBand(p: Priority) {
    bands = bands.includes(p) ? bands.filter((x) => x !== p) : [...bands, p].sort();
  }

  function exportStories() {
    if (!grouped) {
      const articles = rows.map((r) => ({
        priority: r.story.priority,
        title: r.title,
        url: r.url,
        source: r.feed,
        source_tier: r.tier,
        published: r.date,
        story_id: r.story.id,
        story_title: r.story.title,
        role: r.index === 0 ? 'lead' : 'duplicate',
        cves: r.story.cves.join(' '),
      }));
      download(`cyberdigest-articles-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(articles), 'text/csv');
      return;
    }
    const out = visible.map((s) => ({
      priority: s.priority,
      title: s.title,
      url: s.url,
      lead_source: s.feed,
      sources: s.sourceCount,
      reasons: s.reasons.map((r) => r.label).join('; '),
      cves: s.cves.join(' '),
      vendors: s.vendors.join('; '),
      actors: s.actors.join('; '),
      malware: s.malware.join('; '),
      first_reported: s.date,
      last_activity: s.lastSeen,
    }));
    download(`cyberdigest-stories-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(out), 'text/csv');
  }

  function onKey(e: KeyboardEvent) {
    const target = e.target as HTMLElement;
    const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (!document.querySelector('dialog[open]')) void palette?.open();
      return;
    }
    if (document.querySelector('dialog[open]')) return;
    if (e.key === 'Escape') {
      if (typing) target.blur();
      else if (detailOpen) detailOpen = false;
      else if (railOpen) railOpen = false;
      else setSelection(null);
      return;
    }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    const sel = selected;
    switch (e.key) {
      case 'j':
      case 'ArrowDown':
        if (view !== 'stories') return;
        e.preventDefault();
        move(1);
        break;
      case 'k':
      case 'ArrowUp':
        if (view !== 'stories') return;
        e.preventDefault();
        move(-1);
        break;
      case 'o':
      case 'Enter':
        if (sel) detailOpen = true;
        break;
      case 'v': {
        const href = sel && safeHref(sel.url);
        if (href) window.open(href, '_blank', 'noopener,noreferrer');
        break;
      }
      case 'w':
        if (sel) toggleIn(prefs.starred, sel.id);
        break;
      case 'm':
        if (sel && view === 'stories') hideSelected(sel);
        break;
      case '/':
        e.preventDefault();
        searchEl?.focus();
        break;
      case '1':
        view = 'overview';
        break;
      case '2':
        view = 'stories';
        break;
      case '3':
        view = 'cves';
        break;
      case '4':
        view = 'sources';
        break;
      case '5':
        view = 'ransomware';
        break;
      case 'p':
        toggleBand(4);
        break;
      case 'd':
        if (view === 'stories') toggleGrouping();
        break;
      case 't':
        prefs.theme = prefs.theme === 'dark' ? 'light' : 'dark';
        break;
      case '?':
        helpDialog?.open();
        break;
    }
  }
</script>

<svelte:window onkeydown={onKey} />

<div class="app">
  <header class="topbar">
    <button class="brand" onclick={() => (view = 'overview')} title="CyberDigest: Overview" aria-label="CyberDigest, go to Overview">
      <!-- Two colourways of the same logo; the active theme shows exactly one. -->
      <img class="logo logo-on-dark" src="./brand/logo-dark.png" alt="CyberDigest" width="136" height="31" decoding="async" />
      <img class="logo logo-on-light" src="./brand/logo-light.png" alt="CyberDigest" width="136" height="31" decoding="async" />
    </button>

    <nav class="views" aria-label="Views">
      <button aria-current={view === 'overview' ? 'page' : undefined} onclick={() => (view = 'overview')}>Overview</button>
      <button aria-current={view === 'stories' ? 'page' : undefined} onclick={() => (view = 'stories')}>Stories</button>
      <button aria-current={view === 'cves' ? 'page' : undefined} onclick={() => (view = 'cves')}>CVEs</button>
      <button aria-current={view === 'ransomware' || view === 'group' ? 'page' : undefined} onclick={() => (view = 'ransomware')}>Ransomware</button>
      <button aria-current={view === 'sources' ? 'page' : undefined} onclick={() => (view = 'sources')}>Sources</button>
    </nav>

    <div class="search">
      <input
        bind:this={searchEl}
        bind:value={query}
        type="search"
        placeholder="Search or filter: vendor:ivanti kev:yes since:7d"
        aria-label="Search stories"
        spellcheck="false"
        autocomplete="off"
        onfocus={() => (searchFocused = true)}
        onblur={() => setTimeout(() => (searchFocused = false), 150)}
        onkeydown={(e) => e.key === 'Enter' && (view = 'stories')}
      />
      <kbd class="search-kbd" aria-hidden="true">/</kbd>
      {#if searchFocused}
        <div class="hints fade-in" role="listbox" aria-label="Filter examples">
          {#each QUERY_HELP as [example, desc] (example)}
            <button role="option" aria-selected="false" onmousedown={(e) => e.preventDefault()} onclick={() => addFilter(example.split(' ')[0]!)}>
              <code>{example}</code><span>{desc}</span>
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="status">
      {#if data}
        <span class="fresh {freshness}" title="Data generated {fmtDateTime(data.meta.generatedAt)}. Refreshes every ~15 min; this page checks every 5 min.">
          <span class="dot" aria-hidden="true"></span>
          {freshness === 'fresh' ? 'Updated' : freshness === 'stale' ? 'Stale: updated' : 'Very stale: updated'}
          {ago(data.meta.generatedAt, now)} ago
        </span>
      {/if}
      <button class="btn small palette-btn" onclick={() => palette?.open()} title="Command palette">Jump to… <kbd>Ctrl K</kbd></button>
      <button class="btn small rail-toggle" aria-pressed={railOpen} onclick={() => (railOpen = !railOpen)}>Signals</button>
      <button class="btn small" onclick={() => watchDialog?.open()} title="Watchlist & mutes">☆ {prefs.watch.length}</button>
      <button class="icon-btn" title="Toggle theme (t)" aria-label="Toggle theme" onclick={() => (prefs.theme = prefs.theme === 'dark' ? 'light' : 'dark')}>◐</button>
      <button class="icon-btn" title="Help & shortcuts (?)" aria-label="Help" onclick={() => helpDialog?.open()}>?</button>
    </div>
  </header>

  {#if error && !data}
    <div class="state">
      <h1>Couldn't load data</h1>
      <p class="muted">{error}</p>
      <p class="muted">If you're running locally, run <code>npm run pipeline</code> first.</p>
      <button class="btn" onclick={() => refresh(true)}>Retry</button>
    </div>
  {:else if !data}
    <div class="state"><p class="muted">Loading…</p></div>
  {:else if view === 'overview'}
    <main class="full" in:fade={{ duration: motion }}>
      <Overview
        overview={data.overview}
        actors={data.actors}
        ransomware={data.ransomware}
        trendDays={data.trends.days}
        onFilter={addFilter}
        onActor={openActor}
        onRansomware={() => (view = 'ransomware')}
        onGroup={openGroup}
      />
    </main>
  {:else if view === 'actor'}
    <main class="full" in:fade={{ duration: motion }}>
      {#if currentActor}
        {#key currentActor.name}
          <ActorView actor={currentActor} {storyById} trendDays={data.trends.days} {now} onBack={() => (view = backView)} onFilter={addFilter} onStory={openStory} />
        {/key}
      {:else}
        <div class="state"><p>No recent activity for “{actorName}”.</p><button class="btn" onclick={() => (view = 'overview')}>Back to Overview</button></div>
      {/if}
    </main>
  {:else if view === 'ransomware'}
    <main class="full" in:fade={{ duration: motion }}>
      <RansomwareView data={data.ransomware} sources={data.sources} onGroup={openGroup} onFilter={addFilter} />
    </main>
  {:else if view === 'group'}
    <main class="full" in:fade={{ duration: motion }}>
      {#if currentGroup}
        {#key currentGroup.id}
          <GroupView group={currentGroup} weeks={data.ransomware.weeks} caveat={data.ransomware.caveat} rvmUpdated={data.ransomware.matrixUpdated.rvm} onBack={() => (view = backView === 'group' ? 'ransomware' : backView)} onFilter={addFilter} />
        {/key}
      {:else}
        <div class="state"><p>No profile for this group.</p><button class="btn" onclick={() => (view = 'ransomware')}>Back to Ransomware</button></div>
      {/if}
    </main>
  {:else if view === 'cves'}
    <main class="full" in:fade={{ duration: motion }}><CveTable cves={data.cves} {now} onFilter={addFilter} /></main>
  {:else if view === 'sources'}
    <main class="full" in:fade={{ duration: motion }}><SourcesView meta={data.meta} health={data.health} sources={data.sources} {now} /></main>
  {:else}
    <div class="layout" in:fade={{ duration: motion }}>
      <aside class="rail scroll" class:open={railOpen} aria-label="Signals">
        <WatchPanel hits={watchHits} {now} onSelect={(id) => select(id, true)} onManage={() => watchDialog?.open()} onShowAll={() => addFilter('is:watched')} />
        <KevPanel kev={data.kev} {now} onFilter={addFilter} />
        <MultiSourcePanel cves={data.cves} {now} onFilter={addFilter} />
        <EpssPanel epss={data.epss} onFilter={addFilter} />
        <TrendsPanel trends={data.trends} onFilter={addFilter} />
        <HealthPanel meta={data.meta} health={data.health} onOpen={() => (view = 'sources')} />
      </aside>

      <main class="list-col">
        <div class="filterbar">
          <div class="bands" role="group" aria-label="Priority bands">
            {#each [1, 2, 3, 4] as const as p (p)}
              <button class="band" aria-pressed={parsed.priority.length ? parsed.priority.includes(p) : bands.includes(p)} disabled={parsed.priority.length > 0} onclick={() => toggleBand(p)}>
                <span class="prio p{p}">P{p}</span>
                <span class="band-label">{PRIORITY_LABELS[p]}</span>
                <span class="num band-n">{bandCounts[p - 1]}</span>
              </button>
            {/each}
          </div>
          <div class="fb-right">
            <div class="seg" role="radiogroup" aria-label="Deduplication" title="Group duplicate coverage into stories, or show every article (d)">
              <button role="radio" aria-checked={grouped} class:on={grouped} onclick={() => !grouped && toggleGrouping()}>Grouped</button>
              <button role="radio" aria-checked={!grouped} class:on={!grouped} onclick={() => grouped && toggleGrouping()}>Every article</button>
            </div>
            <span class="muted num" title={grouped ? 'Articles folded into multi-source stories, and stories hidden by your mutes' : 'Grouping is off: every article from every feed is listed'}>
              {grouped ? `${data.meta.counts.collapsed} duplicates collapsed` : `${rows.length} articles`}{mutedCount ? ` · ${mutedCount} muted` : ''}
            </span>
            <button class="btn small" onclick={exportStories} title="Export the current view as CSV">CSV</button>
          </div>
        </div>
        {#if query.trim()}
          <div class="active-q">
            <span class="muted">{rows.length} {grouped ? (rows.length === 1 ? 'story matches' : 'stories match') : rows.length === 1 ? 'article matches' : 'articles match'}</span>
            <code>{query}</code>
            <button class="btn small" onclick={() => (query = '')}>Clear</button>
          </div>
        {/if}
        <div class="scroll list-scroll">
          {#if visible.length === 0}
            <div class="empty-list">
              <p>No stories match.</p>
              <p class="muted">{bands.includes(4) ? 'Try clearing the search.' : 'Try clearing the search or including P4 (context).'}</p>
            </div>
          {:else}
            <StoryList
              rows={rows.slice(0, limit)}
              total={rows.length}
              {grouped}
              {selectedKey}
              selectedStoryId={selectedId}
              {now}
              {cveInfo}
              {actors}
              {isNew}
              {isWatched}
              {isStarred}
              isArrived={(s) => arrived.has(s.id)}
              onSelect={(id) => select(id)}
              onOpen={(id) => select(id, true)}
              onActor={openActor}
              onMore={() => (limit += PAGE)}
            />
          {/if}
        </div>
      </main>

      <section class="detail-col scroll" class:open={detailOpen && selected} aria-label="Detail">
        {#if selected}
          {#key selected.id}
            <div in:fade={{ duration: motion }}>
              <DetailPane story={selected} {cveInfo} {actors} {now} onFilter={addFilter} onActor={openActor} onGroup={openGroup} onClose={() => ((detailOpen = false), setSelection(null))} />
            </div>
          {/key}
        {:else}
          <div class="briefing">
            <h2>Briefing</h2>
            {#if newCounts}
              <p>
                <b class="num">{newCounts.total}</b> new stories since your last visit ({fmtDateTime(previousVisit ?? undefined)})
                {#if newCounts.p1 || newCounts.p2}: <b class="num">{newCounts.p1}</b> P1 and <b class="num">{newCounts.p2}</b> P2.{/if}
              </p>
              {#if newCounts.total}<button class="btn small" onclick={() => addFilter('is:new')}>Show only new</button>{/if}
            {:else}
              <p>Welcome. Stories you haven't seen yet will be marked with a dot on your next visit.</p>
            {/if}
            <p class="muted">
              {bandCounts[0]} P1 and {bandCounts[1]} P2 stories in the last 14 days, from {data.meta.counts.items} feed items across {data.meta.counts.feedsTotal} sources.
            </p>
            <p class="muted">Select a story (<kbd>j</kbd>/<kbd>k</kbd>) to see its sources, CVE enrichment and entities. Press <kbd>?</kbd> for rules and shortcuts.</p>
          </div>
        {/if}
      </section>
    </div>
  {/if}
</div>

<WatchlistDialog bind:this={watchDialog} />
<HelpDialog bind:this={helpDialog} />
<CommandPalette bind:this={palette} search={commands} />
<Toasts />

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    height: 52px;
    padding: 0 14px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    flex: none;
  }
  .brand {
    display: flex;
    align-items: center;
    flex: none;
    padding: 2px 4px;
    margin-left: -4px;
    border-radius: 6px;
  }
  .logo {
    display: block;
    height: 31px;
    width: auto;
  }
  /* Show the colourway that matches the active theme (dark is the default). */
  .logo-on-light {
    display: none;
  }
  :global(:root[data-theme='light']) .logo-on-light {
    display: block;
  }
  :global(:root[data-theme='light']) .logo-on-dark {
    display: none;
  }
  .views {
    display: flex;
    gap: 2px;
  }
  .views button {
    padding: 5px 10px;
    border-radius: 6px;
    color: var(--muted);
    font-weight: 500;
  }
  .views button:hover {
    color: var(--text);
  }
  .views button[aria-current='page'] {
    background: var(--surface-3);
    color: var(--text);
  }
  .search {
    position: relative;
    flex: 1;
    max-width: 560px;
  }
  .search input {
    width: 100%;
    height: 32px;
    padding: 0 32px 0 10px;
    border: 1px solid var(--border-strong);
    border-radius: 7px;
    background: var(--page);
  }
  .search input:focus {
    outline: 2px solid var(--focus);
    outline-offset: -1px;
  }
  .search-kbd {
    position: absolute;
    right: 8px;
    top: 7px;
  }
  .hints {
    position: absolute;
    top: 38px;
    left: 0;
    right: 0;
    z-index: 20;
    padding: 6px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--surface);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  }
  .hints button {
    display: grid;
    grid-template-columns: 210px 1fr;
    gap: 10px;
    width: 100%;
    padding: 5px 8px;
    border-radius: 5px;
    text-align: left;
    font-size: 12px;
  }
  .hints button:hover {
    background: var(--surface-2);
  }
  .hints code {
    font: 12px ui-monospace, SFMono-Regular, Consolas, monospace;
  }
  .hints span {
    color: var(--muted);
  }
  .status {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .fresh {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--muted);
    white-space: nowrap;
  }
  .fresh .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--good);
  }
  .fresh.stale {
    color: var(--text);
  }
  .fresh.stale .dot {
    background: var(--warning);
  }
  .fresh.very-stale {
    color: var(--text);
    font-weight: 600;
  }
  .fresh.very-stale .dot {
    background: var(--critical);
  }
  .rail-toggle {
    display: none;
  }
  .palette-btn kbd {
    margin-left: 2px;
  }
  @media (max-width: 1500px) {
    .palette-btn {
      display: none;
    }
  }

  .layout {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 310px minmax(0, 1fr) 440px;
  }
  .rail {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 10px;
    border-right: 1px solid var(--border);
    background: var(--page);
  }
  .list-col {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    background: var(--surface);
  }
  .filterbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
  }
  .bands {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }
  .band {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 8px 0 4px;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--muted);
    opacity: 0.75;
  }
  .band[aria-pressed='true'] {
    opacity: 1;
    border-color: var(--border-strong);
    background: var(--surface-2);
    color: var(--text);
  }
  .band:disabled {
    cursor: default;
  }
  .band-label {
    font-size: 12px;
  }
  .band-n {
    font-weight: 600;
  }
  .fb-right {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
  }
  .seg {
    display: inline-flex;
    padding: 2px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--page);
  }
  .seg button {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--muted);
  }
  .seg button.on {
    background: var(--surface-3);
    color: var(--text);
  }
  .active-q {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    background: var(--accent-wash);
  }
  .active-q code {
    font: 12px ui-monospace, SFMono-Regular, Consolas, monospace;
  }
  .list-scroll {
    flex: 1;
    min-height: 0;
  }
  .empty-list {
    padding: 40px 20px;
    text-align: center;
  }
  .detail-col {
    border-left: 1px solid var(--border);
    background: var(--surface);
  }
  .briefing {
    padding: 18px 18px;
  }
  .briefing h2 {
    margin: 0 0 10px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  .full {
    flex: 1;
    min-height: 0;
    background: var(--surface);
  }
  .state {
    padding: 60px 20px;
    text-align: center;
  }

  @media (max-width: 1400px) {
    .layout {
      grid-template-columns: minmax(0, 1fr) 420px;
    }
    .rail {
      display: none;
    }
    .rail.open {
      display: flex;
      position: fixed;
      top: 52px;
      bottom: 0;
      left: 0;
      width: 340px;
      z-index: 30;
      box-shadow: 8px 0 24px rgba(0, 0, 0, 0.4);
    }
    .rail-toggle {
      display: inline-flex;
    }
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
    }
    .detail-col {
      display: none;
    }
    .detail-col.open {
      display: block;
      position: fixed;
      top: 52px;
      bottom: 0;
      right: 0;
      width: min(520px, 100vw);
      z-index: 25;
      box-shadow: -8px 0 24px rgba(0, 0, 0, 0.4);
    }
    .views,
    .fresh {
      display: none;
    }
    .band-label {
      display: none;
    }
  }
</style>
