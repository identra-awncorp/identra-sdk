// Timing harness: warm-up, assert once, calibrate the iteration count so a run lasts >= minMs,
// time every iteration with process.hrtime.bigint(), repeat RUNS times, keep the median run.
const RUNS = 3;
const WARMUP_MS = 500;
const now = () => process.hrtime.bigint();

export const options = { minMs: 2000 };

// Nearest-rank percentile of an ascending Float64Array.
const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];

function stats(times, n) {
  const sorted = Float64Array.from(times).sort();
  let sum = 0;
  for (const t of times) sum += t;
  return { n, totalMs: sum, opsPerSec: (n / sum) * 1000, meanMs: sum / n, p50Ms: pct(sorted, 50), p95Ms: pct(sorted, 95), p99Ms: pct(sorted, 99), maxMs: sorted[n - 1] };
}

async function timedRun(fn, n) {
  const times = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const t0 = now();
    await fn();
    times[i] = Number(now() - t0) / 1e6;
  }
  return stats(times, n);
}

/**
 * fn: the operation (async or sync). check(): throws unless the operation's real result is
 * correct; it runs once before timing and once after (a benchmark of a failing path is worthless).
 */
export async function bench({ name, backend, fn, check }) {
  await check();
  // Warm-up (JIT, caches): at least WARMUP_MS and 10 calls.
  const w0 = now();
  let calls = 0;
  while (calls < 10 || Number(now() - w0) / 1e6 < WARMUP_MS) {
    await fn();
    calls++;
  }
  // Calibrate from a short probe, aim at 1.15 x the minimum run length.
  const probe = await timedRun(fn, Math.max(5, Math.ceil(calls / 3)));
  let n = Math.max(20, Math.ceil((options.minMs * 1.15) / probe.meanMs));
  const runs = [];
  while (runs.length < RUNS) {
    const r = await timedRun(fn, n);
    if (r.totalMs < options.minMs) {
      n = Math.ceil((n * options.minMs * 1.15) / r.totalMs); // too short: grow and redo, discard this one
      continue;
    }
    runs.push(r);
  }
  await check();
  const sorted = [...runs].sort((a, b) => a.opsPerSec - b.opsPerSec);
  const median = sorted[1];
  return { name, backend, ...median, runsOpsPerSec: runs.map((r) => r.opsPerSec), spreadPct: ((sorted[2].opsPerSec - sorted[0].opsPerSec) / median.opsPerSec) * 100 };
}

const fmt = (x) => (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x >= 1 ? x.toFixed(2) : x.toFixed(3));
const int = (x) => Math.round(x).toLocaleString('en-US');

export function table(results) {
  const rows = [
    '| case | backend | ops/s | mean ms | p50 ms | p95 ms | p99 ms | n | run spread |',
    '|---|---|---:|---:|---:|---:|---:|---:|---:|',
  ];
  for (const r of results) {
    rows.push(`| ${r.name} | ${r.backend} | ${r.cold ? fmt(r.opsPerSec) : int(r.opsPerSec)} | ${fmt(r.meanMs)} | ${fmt(r.p50Ms)} | ${r.cold ? '-' : fmt(r.p95Ms)} | ${r.cold ? '-' : fmt(r.p99Ms)} | ${r.n} | ${r.spreadPct.toFixed(1)}% |`);
  }
  return rows.join('\n');
}
