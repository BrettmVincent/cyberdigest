<script lang="ts">
  // Delayed hover/focus card, positioned in viewport coordinates so scroll containers don't clip it.
  import type { Snippet } from 'svelte';
  import { fade } from 'svelte/transition';
  import { place, reducedMotion } from '../lib/actions';

  interface Props {
    children: Snippet;
    card: Snippet;
    delay?: number;
  }
  let { children, card, delay = 350 }: Props = $props();

  let anchor = $state<HTMLSpanElement>();
  let pos = $state<{ x: number; y: number } | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const motion = reducedMotion() ? 0 : 120;

  function show() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (!anchor) return;
      const r = anchor.getBoundingClientRect();
      const x = Math.min(r.left, window.innerWidth - 336);
      const below = r.bottom + 6;
      pos = { x: Math.max(8, x), y: below + 200 > window.innerHeight ? Math.max(8, r.top - 6 - 180) : below };
    }, delay);
  }
  function hide() {
    clearTimeout(timer);
    timer = setTimeout(() => (pos = null), 120);
  }
</script>

<span class="anchor" bind:this={anchor} role="presentation" onpointerenter={show} onpointerleave={hide} onfocusin={show} onfocusout={hide}>
  {@render children()}
</span>
{#if pos}
  <div class="hovercard" use:place={pos} transition:fade={{ duration: motion }} role="tooltip" onpointerenter={() => clearTimeout(timer)} onpointerleave={hide}>
    {@render card()}
  </div>
{/if}

<style>
  .anchor {
    display: inline-flex;
  }
  .hovercard {
    position: fixed;
    z-index: 70;
    width: 320px;
    padding: 10px 12px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--surface-2);
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
    font-size: 12px;
    color: var(--text-2);
    cursor: default;
  }
</style>
