<script lang="ts" module>
  export interface Row {
    key: string;
    label: string;
    value: number;
    /** Secondary text shown after the value, in muted ink. */
    note?: string;
    title?: string;
  }
</script>

<script lang="ts">
  // Ranked horizontal bars (single series). Each row is a button when onSelect is given.
  import { widthPct } from '../../lib/actions';

  interface Props {
    rows: Row[];
    onSelect?: (row: Row) => void;
    empty?: string;
    labelWidth?: 'narrow' | 'wide';
  }
  let { rows, onSelect, empty = 'No data yet.', labelWidth = 'wide' }: Props = $props();
  const max = $derived(Math.max(1, ...rows.map((r) => r.value)));
</script>

{#if rows.length === 0}
  <p class="muted empty">{empty}</p>
{:else}
  <ul class="hbars {labelWidth}">
    {#each rows as r (r.key)}
      <li>
        <svelte:element
          this={onSelect ? 'button' : 'div'}
          class="row"
          class:clickable={!!onSelect}
          title={r.title}
          onclick={onSelect ? () => onSelect(r) : undefined}
          role={onSelect ? undefined : 'group'}
        >
          <span class="label">{r.label}</span>
          <span class="track"><span class="bar" use:widthPct={(r.value / max) * 100}></span></span>
          <span class="val num">{r.value}{#if r.note}<span class="note">{r.note}</span>{/if}</span>
        </svelte:element>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .hbars {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .row {
    display: grid;
    grid-template-columns: minmax(90px, 40%) 1fr 68px;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 3px 4px;
    border-radius: 4px;
    text-align: left;
    font-size: 12px;
  }
  .narrow .row {
    grid-template-columns: minmax(70px, 28%) 1fr 68px;
  }
  .row.clickable:hover {
    background: var(--surface-2);
  }
  .label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-2);
  }
  .track {
    height: 8px;
  }
  .bar {
    display: block;
    height: 8px;
    min-width: 2px;
    border-radius: 0 4px 4px 0;
    background: var(--series-1);
  }
  .row.clickable:hover .bar {
    filter: brightness(1.15);
  }
  .val {
    text-align: right;
    color: var(--text);
    white-space: nowrap;
  }
  .note {
    margin-left: 4px;
    color: var(--muted);
    font-size: 11px;
  }
  .empty {
    margin: 0;
    font-size: 12px;
  }
</style>
