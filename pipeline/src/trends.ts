import type { TrendSeries, Trends } from '../../shared/types';
import { DAY, isoDay } from './util';

export interface TrendStory {
  time: number;
  actors: string[];
  malware: string[];
  vendors: string[];
}

const DAYS = 30;
const RECENT = 7;

/**
 * Daily story counts per entity over 30 days. `baseline` is the expected 7-day count
 * derived from the 23 days before the most recent week (null until there is enough history).
 */
export function buildTrends(stories: TrendStory[], now: number, historyDays: number, top = 12): Trends {
  const today = Date.parse(isoDay(now));
  const days = Array.from({ length: DAYS }, (_, i) => isoDay(today - (DAYS - 1 - i) * DAY));
  const dayIndex = new Map(days.map((d, i) => [d, i]));

  const series = (kind: TrendSeries['kind'], pick: (s: TrendStory) => string[]): TrendSeries[] => {
    const counts = new Map<string, number[]>();
    for (const s of stories) {
      const idx = dayIndex.get(isoDay(s.time));
      if (idx === undefined) continue;
      for (const name of new Set(pick(s))) {
        let arr = counts.get(name);
        if (!arr) counts.set(name, (arr = new Array<number>(DAYS).fill(0)));
        arr[idx]!++;
      }
    }
    const usable = Math.min(historyDays, DAYS) - RECENT;
    return [...counts.entries()]
      .map(([name, d]) => {
        const last7 = d.slice(-RECENT).reduce((a, b) => a + b, 0);
        const prior = d.slice(DAYS - RECENT - Math.max(usable, 0), DAYS - RECENT);
        const baseline = usable >= 7 ? (prior.reduce((a, b) => a + b, 0) / usable) * RECENT : null;
        const rising = baseline !== null && last7 >= 3 && last7 >= 2 * Math.max(baseline, 1);
        return { name, kind, days: d, last7, baseline: baseline === null ? null : Math.round(baseline * 10) / 10, rising };
      })
      .filter((s) => s.last7 >= 2)
      .sort((a, b) => Number(b.rising) - Number(a.rising) || b.last7 - a.last7 || a.name.localeCompare(b.name))
      .slice(0, top);
  };

  return {
    days,
    historyDays,
    actors: series('actor', (s) => s.actors),
    malware: series('malware', (s) => s.malware),
    vendors: series('vendor', (s) => s.vendors),
  };
}
