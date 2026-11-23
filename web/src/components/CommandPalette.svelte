<script lang="ts" module>
  export interface Command {
    id: string;
    group: string;
    label: string;
    hint?: string;
    run: () => void;
  }
</script>

<script lang="ts">
  import { tick } from 'svelte';

  interface Props {
    search: (query: string) => Command[];
  }
  let { search }: Props = $props();

  let dialog = $state<HTMLDialogElement>();
  let input = $state<HTMLInputElement>();
  let query = $state('');
  let active = $state(0);

  const results = $derived(search(query.trim()));

  export async function open() {
    query = '';
    active = 0;
    dialog?.showModal();
    await tick();
    input?.focus();
  }

  function run(c: Command | undefined) {
    if (!c) return;
    dialog?.close();
    c.run();
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      active = Math.min(results.length - 1, active + 1);
      document.getElementById(`cmd-${active}`)?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      active = Math.max(0, active - 1);
      document.getElementById(`cmd-${active}`)?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      e.preventDefault();
      run(results[active]);
    }
  }
</script>

<dialog bind:this={dialog} class="palette" aria-label="Command palette" onclick={(e) => e.target === dialog && dialog?.close()}>
  <input
    bind:this={input}
    bind:value={query}
    oninput={() => (active = 0)}
    onkeydown={onKey}
    placeholder="Jump to a story, CVE, actor, vendor… or type a command"
    aria-label="Command"
    aria-controls="cmd-list"
    aria-activedescendant={results.length ? `cmd-${active}` : undefined}
    role="combobox"
    aria-expanded="true"
    spellcheck="false"
    autocomplete="off"
  />
  <ul id="cmd-list" role="listbox" class="scroll">
    {#each results as c, i (c.id)}
      {#if i === 0 || results[i - 1]?.group !== c.group}<li class="group" role="presentation">{c.group}</li>{/if}
      <li id="cmd-{i}" role="option" aria-selected={i === active} class:active={i === active} onclick={() => run(c)} onpointermove={() => (active = i)} onkeydown={() => {}}>
        <span class="label">{c.label}</span>
        {#if c.hint}<span class="hint">{c.hint}</span>{/if}
      </li>
    {:else}
      <li class="none">No matches.</li>
    {/each}
  </ul>
  <footer><kbd>↑</kbd><kbd>↓</kbd> navigate <kbd>Enter</kbd> open <kbd>Esc</kbd> close</footer>
</dialog>

<style>
  .palette {
    width: min(640px, calc(100vw - 32px));
    margin-top: 12vh;
    padding: 0;
  }
  input {
    width: 100%;
    height: 48px;
    padding: 0 16px;
    border: 0;
    border-bottom: 1px solid var(--border);
    background: transparent;
    font-size: 15px;
    outline: none;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 6px;
    max-height: 52vh;
  }
  .group {
    padding: 8px 10px 4px;
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--muted);
  }
  li[role='option'] {
    display: flex;
    align-items: baseline;
    gap: 10px;
    padding: 7px 10px;
    border-radius: 6px;
    cursor: pointer;
  }
  li.active {
    background: var(--accent-wash);
    box-shadow: inset 2px 0 0 var(--accent);
  }
  .label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .hint {
    color: var(--muted);
    font-size: 11.5px;
    white-space: nowrap;
  }
  .none {
    padding: 14px;
    color: var(--muted);
  }
  footer {
    display: flex;
    gap: 6px;
    align-items: center;
    padding: 8px 12px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11.5px;
  }
</style>
