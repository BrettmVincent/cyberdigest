import { describe, expect, it } from 'vitest';
import { canonicalUrl, clamp, jaccard, titleTokens, toPlainText } from '../src/text';

describe('toPlainText', () => {
  it('strips tags and decodes entities', () => {
    expect(toPlainText('<p>Patch <b>now</b> &amp; reboot&nbsp;&#8212; CVE&#x2d;2026&#8209;1</p>')).toBe('Patch now & reboot — CVE-2026‑1');
  });

  it('removes script/style blocks and event-handler markup (XSS payloads)', () => {
    const out = toPlainText('<img src=x onerror="alert(1)"><script>alert(2)</script><style>*{}</style>hello<svg onload=alert(3)>x</svg>');
    expect(out).toBe('hello');
    expect(out).not.toMatch(/[<>]/);
  });

  it('handles double-encoded HTML without leaving markup behind', () => {
    const out = toPlainText('&lt;script&gt;alert(1)&lt;/script&gt;&lt;b&gt;bold&lt;/b&gt;');
    expect(out).not.toMatch(/[<>]/);
    expect(out).toContain('bold');
  });

  it('drops stray angle brackets', () => {
    expect(toPlainText('a < b > c')).toBe('a b c');
  });
});

describe('canonicalUrl', () => {
  it('rejects non-http schemes', () => {
    expect(canonicalUrl('javascript:alert(1)')).toBeNull();
    expect(canonicalUrl('data:text/html,<b>x</b>')).toBeNull();
    expect(canonicalUrl('vbscript:msgbox')).toBeNull();
  });

  it('strips tracking parameters and fragments', () => {
    expect(canonicalUrl('https://Example.com/a?utm_source=x&id=7&fbclid=y#top')).toBe('https://example.com/a?id=7');
  });

  it('resolves relative links against the feed URL', () => {
    expect(canonicalUrl('/post/1', 'https://blog.example.com/feed')).toBe('https://blog.example.com/post/1');
  });

  it('rejects URLs with embedded credentials', () => {
    expect(canonicalUrl('https://user:pass@example.com/')).toBeNull();
  });
});

describe('clamp', () => {
  it('cuts on a word boundary and adds an ellipsis', () => {
    expect(clamp('alpha beta gamma delta epsilon', 20)).toBe('alpha beta gamma…');
    expect(clamp('short', 20)).toBe('short');
  });
});

describe('titleTokens / jaccard', () => {
  it('ignores stopwords, months and years', () => {
    expect([...titleTokens('The November 2026 Security Update Review')]).toEqual(['review']);
  });

  it('scores near-duplicate headlines highly', () => {
    const a = titleTokens('Fortinet warns of FortiWeb zero-day exploited in attacks');
    const b = titleTokens('Fortinet warns FortiWeb zero-day is exploited in attacks');
    expect(jaccard(a, b)).toBeGreaterThan(0.8);
  });
});
