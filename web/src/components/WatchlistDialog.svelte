<script lang="ts">
  import { download } from '../lib/format';
  import { importPrefs, parseTerm, prefs, type TermKind } from '../lib/prefs.svelte';

  let dialog = $state<HTMLDialogElement | undefined>();
  let kind = $state<TermKind>('vendor');
  let value = $state('');
  let list = $state<'watch' | 'mute'>('watch');
  let message = $state('');

  export function open() {
    message = '';
    dialog?.showModal();
  }

  function add(e: SubmitEvent) {
    e.preventDefault();
    const v = value.trim().replace(/\s+/g, ' ').slice(0, 120);
    if (!v) return;
    const t = `${kind}:${kind === 'cve' ? v.toUpperCase() : v}`;
    if (!prefs[list].includes(t)) prefs[list].push(t);
    value = '';
  }

  function remove(which: 'watch' | 'mute', t: string) {
    prefs[which].splice(prefs[which].indexOf(t), 1);
  }

  function exportJson() {
    download('cyberdigest-watchlist.json', JSON.stringify({ watch: prefs.watch, mute: prefs.mute }, null, 2), 'application/json');
  }

  async function importJson(e: Event) {
    const file = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      if (file.size > 512_000) throw new Error('file too large');
      const { added } = importPrefs(await file.text());
      message = `Imported ${added} new term${added === 1 ? '' : 's'}.`;
    } catch (err) {
      message = `Import failed: ${err instanceof Error ? err.message : 'invalid file'}`;
    }
  }

  const kinds: { id: TermKind; label: string }[] = [
    { id: 'vendor', label: 'Vendor / product' },
    { id: 'actor', label: 'Threat actor' },
    { id: 'malware', label: 'Malware' },
    { id: 'cve', label: 'CVE' },
    { id: 'kw', label: 'Keyword (headline)' },
  ];
  const kindLabel = (t: string) => kinds.find((k) => k.id === parseTerm(t)?.kind)?.label ?? '';
</script>

<dialog bind:this={dialog} aria-labelledby="wl-h" onclick={(e) => e.target === dialog && dialog?.close()}>
  <header>
    <h2 id="wl-h">Watchlist &amp; mutes</h2>
    <button class="icon-btn" aria-label="Close" onclick={() => dialog?.close()}>✕</button>
  </header>
  <div class="body">
    <p class="muted">
      Watched terms float matching stories to the top of their priority band and fill the Watchlist panel. Muted terms hide stories (a watched term
      always wins). Stored only in this browser.
    </p>
    <form onsubmit={add}>
      <select bind:value={list} aria-label="List">
        <option value="watch">Watch</option>
        <option value="mute">Mute</option>
      </select>
      <select bind:value={kind} aria-label="Term type">
        {#each kinds as k (k.id)}<option value={k.id}>{k.label}</option>{/each}
      </select>
      <input bind:value placeholder={kind === 'vendor' ? 'e.g. Fortinet, Ivanti, VMware' : kind === 'cve' ? 'CVE-2026-1234' : kind === 'actor' ? 'e.g. APT28' : kind === 'malware' ? 'e.g. LockBit' : 'e.g. citrix'} aria-label="Value" />
      <button class="btn" type="submit">Add</button>
    </form>
    <p class="hint muted">Vendor, actor and malware names must match the canonical names shown on stories (e.g. "Palo Alto Networks", "APT28").</p>

    {#each [['watch', 'Watching'], ['mute', 'Muted']] as const as [which, label] (which)}
      <h3>{label} <span class="muted num">({prefs[which].length})</span></h3>
      {#if prefs[which].length === 0}
        <p class="muted none">None.</p>
      {:else}
        <ul class="terms">
          {#each prefs[which] as t (t)}
            <li>
              <span class="kind muted">{kindLabel(t)}</span>
              <span class="val">{parseTerm(t)?.value}</span>
              <button class="icon-btn" aria-label="Remove {t}" onclick={() => remove(which, t)}>✕</button>
            </li>
          {/each}
        </ul>
      {/if}
    {/each}

    <div class="io">
      <button class="btn small" onclick={exportJson}>Export JSON</button>
      <label class="btn small">Import JSON<input type="file" accept="application/json,.json" class="sr-only" onchange={importJson} /></label>
      {#if prefs.hidden.length}<button class="btn small" onclick={() => prefs.hidden.splice(0)}>Unhide {prefs.hidden.length} hidden stories</button>{/if}
      {#if message}<span class="muted" role="status">{message}</span>{/if}
    </div>
  </div>
</dialog>

<style>
  form {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  select,
  input {
    height: 28px;
    padding: 0 8px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--page);
  }
  input {
    flex: 1;
    min-width: 160px;
  }
  .hint {
    font-size: 11.5px;
    margin: 6px 0 0;
  }
  h3 {
    margin: 18px 0 6px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  .none {
    margin: 0;
  }
  .terms {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .terms li {
    display: grid;
    grid-template-columns: 130px 1fr auto;
    align-items: center;
    padding: 3px 0;
    border-bottom: 1px solid var(--border);
  }
  .kind {
    font-size: 11.5px;
  }
  .io {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-top: 18px;
  }
</style>
