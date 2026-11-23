// Re-test every feed in config/feeds.yaml and print a status table.
//   npm run check-feeds            enabled feeds
//   npm run check-feeds -- --all   include disabled (tier D) entries
import { loadFeeds } from '../src/feeds';
import { decodeText, fetchRaw } from '../src/fetch';
import { parseFeed } from '../src/parse';
import { errMsg, pool } from '../src/util';

const all = process.argv.includes('--all');
const feeds = loadFeeds().filter((f) => all || f.enabled);

const rows = await pool(feeds, 8, async (f) => {
  const res = await fetchRaw(f.url, { headers: f.headers });
  let status = res.status === 'ok' ? 'ok' : `FAIL ${res.error ?? res.httpStatus}`;
  let items = 0;
  let newest = '';
  if (res.status === 'ok' && res.data) {
    try {
      const entries = parseFeed(decodeText(res.data, res.contentType));
      items = entries.length;
      newest = entries.map((e) => e.published ?? '').sort().at(-1)?.slice(0, 10) ?? '';
      if (items === 0) status = 'EMPTY';
    } catch (e) {
      status = `FAIL ${errMsg(e)}`;
    }
  }
  return { id: f.id, tier: f.tier, enabled: f.enabled ? '' : 'disabled', status, items, newest, kb: Math.round(res.bytes / 1024), ms: res.ms };
});

console.table(rows);
const failed = rows.filter((r) => r.status !== 'ok');
console.log(`${rows.length - failed.length}/${rows.length} OK`);
process.exitCode = failed.some((r) => r.enabled === '') ? 1 : 0;
