<script lang="ts">
  import { QUERY_HELP } from '../lib/query';

  let dialog = $state<HTMLDialogElement | undefined>();
  export function open() {
    dialog?.showModal();
  }

  const keys: [string, string][] = [
    ['j / k', 'next / previous story'],
    ['o or Enter', 'open the detail pane'],
    ['v', 'open the original article in a new tab'],
    ['w', 'star / unstar the selected story'],
    ['m', 'hide the selected story'],
    ['Ctrl+K', 'command palette: jump to any story, CVE, actor or action'],
    ['/', 'search / filter stories'],
    ['Esc', 'clear selection / leave search'],
    ['1 / 2 / 3 / 4 / 5', 'Overview / Stories / CVEs / Sources / Ransomware'],
    ['p', 'toggle P4 (context) stories'],
    ['d', 'toggle deduplication: grouped stories ↔ every article'],
    ['t', 'toggle light / dark theme'],
    ['?', 'this help'],
  ];

  const rules: [string, string][] = [
    ['P1 Act now', 'CVE added to CISA KEV in the last 7 days; KEV + ransomware use due within 14 days; CISA SSVC "active" on a CVE from the last 30 days; or a government/vendor advisory says it is exploited. A CVE only listed in passing in a round-up caps at P2.'],
    ['P2 High', 'KEV entry from the last year; exploitation reported by research/news; listed as exploited by ENISA, Shadowserver or another catalogue but not yet by CISA (CIRCL); honeypot exploitation in the last 7 days; CISA newly linked the CVE to ransomware; a ransomware group is known to use a recent KEV or high-EPSS CVE (Ransomware Vulnerability Matrix); EPSS ≥ 8.8% with CVSS ≥ 7 (CVEs from the last year); EPSS up 10+ points in a day; public PoC in the last 72h on a high-severity CVE; or 3+ independent sources within 24h.'],
    ['P3 Monitor', 'Non-bulk advisories, and research that names a CVE, threat actor or malware family.'],
    ['P4 Context', 'Everything else, including bulk advisory streams (MSRC, distro notices, ZDI) unless a rule above fires. Hidden by default.'],
  ];
</script>

<dialog bind:this={dialog} aria-labelledby="help-h" onclick={(e) => e.target === dialog && dialog?.close()}>
  <header>
    <h2 id="help-h">How CyberDigest works</h2>
    <button class="icon-btn" aria-label="Close" onclick={() => dialog?.close()}>✕</button>
  </header>
  <div class="body">
    <h3>Priority rules</h3>
    <dl>
      {#each rules as [k, v] (k)}<dt>{k}</dt><dd>{v}</dd>{/each}
    </dl>
    <p class="muted">Within a band: watched stories first, then most recent activity and number of sources. Every story shows the rules that fired.</p>

    <h3>Keyboard</h3>
    <dl class="keys">
      {#each keys as [k, v] (k)}<dt><kbd>{k}</kbd></dt><dd>{v}</dd>{/each}
    </dl>

    <h3>Search</h3>
    <p class="muted">Free text matches headlines, summaries, CVEs and entities. Combine with filters; the search is kept in the URL so views can be shared.</p>
    <dl class="keys">
      {#each QUERY_HELP as [k, v] (k)}<dt><code>{k}</code></dt><dd>{v}</dd>{/each}
    </dl>
  </div>
</dialog>

<style>
  h3 {
    margin: 16px 0 6px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-2);
  }
  h3:first-child {
    margin-top: 0;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 14px;
    margin: 0;
  }
  dt {
    font-weight: 600;
  }
  dd {
    margin: 0;
    color: var(--text-2);
  }
  code {
    font: 12px ui-monospace, SFMono-Regular, Consolas, monospace;
    color: var(--text);
  }
</style>
