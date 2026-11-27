// List rows for the Stories view. Grouped mode: one row per story (duplicate coverage collapsed).
// Every-article mode: one row per article, each still linked to the story it belongs to.
import type { SourceTier, Story } from '../../../shared/types';

export interface ListRow {
  key: string;
  story: Story;
  title: string;
  url: string;
  feed: string;
  tier: SourceTier;
  date: string;
  /** Position of this article in its story (0 = lead) and the story's article count. */
  index: number;
  count: number;
}

export function groupedRows(stories: Story[]): ListRow[] {
  return stories.map((s) => ({
    key: s.id,
    story: s,
    title: s.title,
    url: s.url,
    feed: s.feed,
    tier: s.tier,
    date: s.lastSeen,
    index: 0,
    count: s.sources.length + 1,
  }));
}

/** Every article as its own row, newest article first regardless of priority. */
export function articleRows(stories: Story[]): ListRow[] {
  const rows: ListRow[] = [];
  for (const s of stories) {
    const count = s.sources.length + 1;
    rows.push({ key: `${s.id}~0`, story: s, title: s.title, url: s.url, feed: s.feed, tier: s.tier, date: s.leadDate ?? s.date, index: 0, count });
    s.sources.forEach((src, i) => {
      rows.push({ key: `${s.id}~${i + 1}`, story: s, title: src.title, url: src.url, feed: src.feed, tier: src.tier, date: src.date, index: i + 1, count });
    });
  }
  const order = new Map(stories.map((s, i) => [s.id, i]));
  return rows.sort(
    (a, b) =>
      b.date.localeCompare(a.date) ||
      a.story.priority - b.story.priority ||
      order.get(a.story.id)! - order.get(b.story.id)! ||
      a.index - b.index,
  );
}

export const storyIdOf = (key: string) => key.split('~')[0]!;
