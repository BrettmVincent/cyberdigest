import { describe, expect, it } from 'vitest';
import type { Story } from '../../shared/types';
import { articleRows, groupedRows, storyIdOf } from '../../web/src/lib/rows';

function story(id: string, priority: 1 | 2 | 3 | 4, leadDate: string, sources: [string, string][]): Story {
  return {
    id,
    title: `${id} lead`,
    url: `https://x/${id}`,
    summary: '',
    feedId: 'f',
    feed: 'Lead feed',
    tier: 'A',
    group: 'news',
    date: leadDate,
    leadDate,
    firstSeen: leadDate,
    lastSeen: leadDate,
    priority,
    reasons: [],
    sources: sources.map(([feed, date], i) => ({ feedId: feed, feed, tier: 'C', title: `${id} dup ${i + 1}`, url: `https://y/${id}/${i}`, date })),
    sourceCount: sources.length + 1,
    cves: [],
    vendors: [],
    actors: [],
    malware: [],
    countries: [],
    exploited: false,
  };
}

const stories = [
  story('a', 1, '2026-11-20T00:00:00Z', [
    ['News1', '2026-11-22T00:00:00Z'],
    ['News2', '2026-11-19T00:00:00Z'],
  ]),
  story('b', 2, '2026-11-23T00:00:00Z', []),
];

describe('list rows (deduplication toggle)', () => {
  it('grouped: one row per story, keyed by story id', () => {
    const rows = groupedRows(stories);
    expect(rows.map((r) => [r.key, r.count])).toEqual([
      ['a', 3],
      ['b', 1],
    ]);
  });

  it('every article: one row per article, newest first within each priority band', () => {
    const rows = articleRows(stories);
    expect(rows.map((r) => [r.key, r.title, r.feed])).toEqual([
      ['a~1', 'a dup 1', 'News1'],
      ['a~0', 'a lead', 'Lead feed'],
      ['a~2', 'a dup 2', 'News2'],
      ['b~0', 'b lead', 'Lead feed'],
    ]);
    expect(rows.every((r) => storyIdOf(r.key) === r.story.id)).toBe(true);
  });
});
