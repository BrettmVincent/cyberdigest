<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    subtitle?: string;
    /** Optional table view (accessibility / exact numbers). */
    table?: Snippet;
    legend?: Snippet;
    actions?: Snippet;
    children: Snippet;
    class?: string;
  }
  let { title, subtitle, table, legend, actions, children, class: cls = '' }: Props = $props();
  let showTable = $state(false);
  const id = `cc-${Math.random().toString(36).slice(2, 8)}`;
</script>

<section class="panel card {cls}" aria-labelledby={id}>
  <header>
    <div>
      <h2 {id}>{title}</h2>
      {#if subtitle}<div class="panel-sub">{subtitle}</div>{/if}
    </div>
    <div class="tools">
      {@render actions?.()}
      {#if table}
        <button class="btn small" aria-pressed={showTable} onclick={() => (showTable = !showTable)} title="Show the data as a table">Table</button>
      {/if}
    </div>
  </header>
  {#if legend && !showTable}<div class="legend">{@render legend()}</div>{/if}
  <div class="body">
    {#if showTable && table}
      <div class="scroll tbl">{@render table()}</div>
    {:else}
      {@render children()}
    {/if}
  </div>
</section>

<style>
  .card {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  header {
    align-items: flex-start !important;
  }
  .tools {
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    padding: 0 12px 4px;
    font-size: 11.5px;
    color: var(--text-2);
  }
  .body {
    flex: 1;
    padding: 4px 12px 12px;
    min-height: 0;
  }
  .tbl {
    max-height: 320px;
  }
  :global(.legend-key) {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  :global(.legend-swatch) {
    width: 10px;
    height: 10px;
    border-radius: 2px;
    display: inline-block;
  }
</style>
