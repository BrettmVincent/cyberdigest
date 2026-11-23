<script lang="ts">
  // Headline number with its baseline (last week) and an animated count-up.
  import { cubicOut } from 'svelte/easing';
  import { Tween } from 'svelte/motion';
  import { reducedMotion } from '../../lib/actions';

  interface Props {
    label: string;
    value: number;
    /** Last week's value; null when there is no meaningful baseline (then `note` is shown). */
    previous: number | null;
    note?: string;
    hint: string;
    onSelect?: () => void;
  }
  let { label, value, previous, note = '', hint, onSelect }: Props = $props();

  const shown = new Tween(0, { duration: reducedMotion() ? 0 : 900, easing: cubicOut });
  $effect(() => {
    shown.target = value;
  });

  const deltaText = $derived.by(() => {
    if (previous === null) return note;
    const delta = value - previous;
    return delta === 0 ? `same as last week (${previous})` : `${delta > 0 ? '▲ +' : '▼ −'}${Math.abs(delta)} on last week (${previous})`;
  });
</script>

<svelte:element this={onSelect ? 'button' : 'div'} class="panel tile" class:clickable={!!onSelect} onclick={onSelect} title={hint} role={onSelect ? undefined : 'group'}>
  <span class="label">{label}</span>
  <span class="value num" aria-label={String(value)}>{Math.round(shown.current)}</span>
  <span class="delta">{deltaText}</span>
</svelte:element>

<style>
  .tile {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 12px 14px;
    text-align: left;
    min-width: 0;
  }
  .tile.clickable:hover {
    border-color: var(--border-strong);
    background: var(--surface-2);
  }
  .label {
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-2);
  }
  .value {
    font-size: 30px;
    font-weight: 650;
    line-height: 1.15;
    color: var(--text);
    font-variant-numeric: normal;
  }
  .delta {
    font-size: 12px;
    color: var(--muted);
  }
</style>
