import { describe, expect, it } from 'vitest';
import { NotAFeedError, parseFeed } from '../src/parse';

describe('parseFeed', () => {
  it('parses RSS 2.0 with content:encoded and categories', () => {
    const xml = `<?xml version="1.0"?>
      <rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
        <channel><title>T</title>
          <item>
            <title>Advisory &amp; fix</title>
            <link>https://example.com/a</link>
            <guid isPermaLink="false">abc-1</guid>
            <pubDate>Mon, 23 Nov 2026 10:00:00 GMT</pubDate>
            <description>short</description>
            <content:encoded><![CDATA[<p>Full <b>body</b> CVE-2026-1234</p>]]></content:encoded>
            <category>Vulnerability</category><category>Patch</category>
          </item>
        </channel>
      </rss>`;
    const [e] = parseFeed(xml);
    expect(e).toMatchObject({
      title: 'Advisory & fix',
      link: 'https://example.com/a',
      guid: 'abc-1',
      published: '2026-11-23T10:00:00.000Z',
      categories: ['Vulnerability', 'Patch'],
    });
    expect(e!.body).toContain('CVE-2026-1234');
  });

  it('uses a permalink guid when <link> is missing', () => {
    const xml = `<rss><channel><item><title>x</title><guid>https://example.com/p/9</guid></item></channel></rss>`;
    expect(parseFeed(xml)[0]!.link).toBe('https://example.com/p/9');
  });

  it('parses Atom, preferring rel=alternate links', () => {
    const xml = `<feed xmlns="http://www.w3.org/2005/Atom">
        <entry>
          <title type="html">Atom &lt;i&gt;entry&lt;/i&gt;</title>
          <link rel="self" href="https://example.com/self"/>
          <link rel="alternate" href="https://example.com/post"/>
          <id>tag:example.com,2026:1</id>
          <updated>2026-11-20T08:00:00Z</updated>
          <summary>Sum</summary>
          <category term="research"/>
        </entry>
      </feed>`;
    const [e] = parseFeed(xml);
    expect(e).toMatchObject({ link: 'https://example.com/post', guid: 'tag:example.com,2026:1', published: '2026-11-20T08:00:00.000Z', categories: ['research'] });
  });

  it('parses RSS 1.0 / RDF with dc:date', () => {
    const xml = `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
        <channel><title>D</title></channel>
        <item><title>DSA-6000-1 openssl</title><link>https://www.debian.org/security/2026/dsa-6000</link><dc:date>2026-11-22</dc:date></item>
      </rdf:RDF>`;
    const [e] = parseFeed(xml);
    expect(e).toMatchObject({ title: 'DSA-6000-1 openssl', published: '2026-11-22T00:00:00.000Z' });
  });

  it('rejects HTML pages', () => {
    expect(() => parseFeed('<!DOCTYPE html><html><body>blocked</body></html>')).toThrow(NotAFeedError);
  });
});
