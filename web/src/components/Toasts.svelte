<script lang="ts">
  import { fly } from 'svelte/transition';
  import { reducedMotion } from '../lib/actions';
  import { dismiss, toasts } from '../lib/toast.svelte';

  const motion = reducedMotion() ? 0 : 180;
</script>

<div class="toasts" aria-live="polite" aria-relevant="additions">
  {#each toasts as t (t.id)}
    <div class="toast" class:alert={t.tone === 'alert'} role="status" transition:fly={{ y: 16, duration: motion }}>
      {#if t.tone === 'alert'}<span class="prio p1" aria-hidden="true">P1</span>{/if}
      <span class="text">{t.text}</span>
      {#if t.action}
        <button
          class="btn small"
          onclick={() => {
            t.action?.run();
            dismiss(t.id);
          }}>{t.action.label}</button
        >
      {/if}
      <button class="icon-btn" aria-label="Dismiss" onclick={() => dismiss(t.id)}>✕</button>
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    right: 16px;
    bottom: 16px;
    z-index: 60;
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: flex-end;
  }
  .toast {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 260px;
    max-width: 420px;
    padding: 9px 10px 9px 12px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--surface-2);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    font-size: 12.5px;
  }
  .toast.alert {
    box-shadow:
      inset 3px 0 0 var(--critical),
      0 8px 24px rgba(0, 0, 0, 0.35);
  }
  .text {
    flex: 1;
  }
</style>
