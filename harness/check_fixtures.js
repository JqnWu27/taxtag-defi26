// Self-check of the fixture files, using NOTHING but the JSON (no chain, no
// harness state): what fixtures/README.md says a reader can do with a file
// is done here, and every root and hash in the file is recomputed.
//
// Per chain:   RCL root from the leaves; every leaf from its fields; the
//              nullifier log against the records; the PSL entries from
//              their fields; at every snapshot the four pinned roots from
//              the listed prefixes (leaf_count, nf_count, at_count, psl_count).
// Per ledger:  id_tax, anchor, AT index from (tag, S); the TA signature;
//              the walk NF_1, NF_2, ... finds exactly the listed records;
//              NF_{n+1} is absent from the nullifier log and from the UNL;
//              the anchor is in the AT; every pledge has its PSL status.
//
// Usage: node harness/check_fixtures.js [file.json ...]   (default: all)
const fs = require("fs");
const path = require("path");
const { init, PARAMS, OP } = require("./lib/hashes");
const { Smt, Rcl } = require("./lib/trees");

const DIR = path.resolve(__dirname, "..", "fixtures");
const B = (x) => BigInt(x);

async function smtOf(F, pairs) {
  const t = await Smt.create(F);
  for (const [k, v] of pairs) await t.insert(B(k), B(v));
  return t;
}

async function checkFile(file, c) {
  const H = c.H, F = c.F;
  const fx = JSON.parse(fs.readFileSync(file, "utf8"));
  let n = 0;
  const bad = [];
  const ok = (cond, what) => { n++; if (!cond) bad.push(what); };

  ok(fx.schema === "taxtag-recording-fixture/1", "schema id");
  ok(B(fx.keyset.digest) === H.P([H.P(fx.keyset.pubx), H.P(fx.keyset.puby)]), "keyset digest");

  const chains = [];
  for (const ch of fx.chains) {
    const cid = B(ch.cid);
    const rcl = new Rcl(H, ch.rcl.depth);
    for (const l of ch.rcl.leaves) rcl.append(B(l));
    ok(rcl.root() === B(ch.rcl.root), `chain ${cid}: RCL root`);
    ok(ch.records.length === ch.rcl.leaves.length && ch.nf_log.length === ch.records.length,
      `chain ${cid}: one record and one logged nullifier per leaf`);
    ch.records.forEach((r, k) => {
      const f = Object.fromEntries(["nf", "cid", "block", "idx", "time", "op", "asset_in", "amount_in",
        "asset_out", "amount_out", "value", "position_id"].map((x) => [x, B(r[x])]));
      const h = H.recordLeaf(f);
      ok(h.leaf === B(r.leaf) && h.meta === B(r.meta) && h.body === B(r.body) && h.tail === B(r.tail),
        `chain ${cid}: leaf ${k} from its fields`);
      ok(r.leaf_index === k && B(ch.rcl.leaves[k]) === h.leaf && B(ch.nf_log[k]) === f.nf && f.cid === cid,
        `chain ${cid}: leaf ${k} position, log entry and chain id`);
    });
    // merge keys strictly increasing in write order within a chain
    const keys = [...ch.records.map((r) => [B(r.time), B(r.block), B(r.idx)]),
                  ...ch.psl.entries.map((e) => [B(e.time), B(e.block), B(e.idx)])];
    const uniq = new Set(keys.map((k) => k.join(":")));
    ok(uniq.size === keys.length, `chain ${cid}: (time, block, idx) unique over records and PSL entries`);
    ch.psl.entries.forEach((e, k) => {
      const f = Object.fromEntries(["kind", "cid", "block", "idx", "time", "asset_a", "amount_a",
        "asset_b", "amount_b", "value"].map((x) => [x, B(e[x])]));
      const h = H.passiveEntry(f);
      ok(h.pentry === B(e.pentry) && h.pmeta === B(e.pmeta) && h.pbody === B(e.pbody),
        `chain ${cid}: PSL entry ${k} from its fields`);
    });
    const pslPairs = ch.psl.entries.map((e) => [e.position_id, e.pentry]);
    const unlPairs = ch.nf_log.map((x) => [x, 1]);
    ok((await smtOf(F, ch.at.leaves)).root() === B(ch.at.root), `chain ${cid}: AT root`);
    ok((await smtOf(F, ch.trl.leaves)).root() === B(ch.trl.root), `chain ${cid}: TRL root`);
    ok((await smtOf(F, pslPairs)).root() === B(ch.psl.root), `chain ${cid}: PSL root`);
    ok((await smtOf(F, unlPairs.slice(0, ch.unl.covered))).root() === B(ch.unl.root), `chain ${cid}: UNL root`);
    ok(ch.unl.leaves.every((l, k) => B(l[0]) === B(ch.nf_log[k]) && B(l[1]) === 1n),
      `chain ${cid}: UNL leaves are the log prefix with value 1`);
    for (const s of ch.snapshots) {
      ok(rcl.root(s.leaf_count) === B(s.root_rcl), `chain ${cid} snapshot ${s.period}: RCL root over ${s.leaf_count} leaves`);
      ok((await smtOf(F, unlPairs.slice(0, s.nf_count))).root() === B(s.root_unl), `chain ${cid} snapshot ${s.period}: UNL root`);
      ok((await smtOf(F, ch.at.leaves.slice(0, s.at_count))).root() === B(s.root_at), `chain ${cid} snapshot ${s.period}: AT root`);
      ok((await smtOf(F, pslPairs.slice(0, s.psl_count))).root() === B(s.root_psl), `chain ${cid} snapshot ${s.period}: PSL root`);
      ok(s.nf_count === s.leaf_count, `chain ${cid} snapshot ${s.period}: UNL covers the log at the pin`);
    }
    const last = ch.snapshots[ch.snapshots.length - 1];
    chains.push({
      ch, cid, acaddr: B(ch.acaddr), last,
      byNf: new Map(ch.records.map((r) => [r.nf, r])),
      unl: await smtOf(F, unlPairs.slice(0, last.nf_count)),
      at: await smtOf(F, ch.at.leaves.slice(0, last.at_count)),
      psl: await smtOf(F, pslPairs.slice(0, last.psl_count)),
    });
  }

  let ledgers = 0, opened = 0;
  for (const tp of fx.taxpayers) {
    for (const t of tp.tags) {
      const tag = B(t.tag), S = B(t.S);
      const idTax = H.idTax(tag, S);
      ok(idTax === B(t.id_tax) && H.anchor(S) === B(t.anchor) && H.atIndex(tag) === B(t.at_index),
        `${t.name}: id_tax, anchor, AT index`);
      const sig = { R8: [F.e(B(t.credential.R8x)), F.e(B(t.credential.R8y))], S: B(t.credential.S) };
      const pub = [F.e(B(fx.keyset.pubx[t.ta_key_index])), F.e(B(fx.keyset.puby[t.ta_key_index]))];
      ok(c.eddsa.verifyPoseidon(F.e(H.credMsg(tag)), sig, pub), `${t.name}: TA signature on the tag`);
      t.ledgers.forEach((led, k) => {
        const cc = chains[k];
        ledgers++;
        ok(B(led.cid) === cc.cid && B(led.acaddr) === cc.acaddr, `${t.name}@${cc.cid}: chain binding`);
        // walk NF_1, NF_2, ... through the chain's records
        const found = [];
        for (let i = 1n; ; i++) {
          const r = cc.byNf.get(H.nullifier(idTax, cc.cid, cc.acaddr, i).toString());
          if (!r) break;
          found.push({ i, r });
        }
        opened += found.length;
        ok(found.length === led.records.length && found.every((x, j) =>
          x.r.nf === led.records[j].nf && x.r.leaf_index === led.records[j].leaf_index &&
          B(led.records[j].i) === x.i), `${t.name}@${cc.cid}: the nullifier walk finds exactly the listed records`);
        ok(found.every((x, j) => j === 0 || x.r.leaf_index > found[j - 1].r.leaf_index),
          `${t.name}@${cc.cid}: records appear in counter order`);
        const nfNext = H.nullifier(idTax, cc.cid, cc.acaddr, BigInt(found.length + 1));
        ok(nfNext === B(led.nf_next) && led.next_counter === found.length + 1 &&
          !cc.ch.nf_log.includes(nfNext.toString()), `${t.name}@${cc.cid}: NF_{n+1} is not in the log`);
        ok(led.anchored === cc.ch.at.leaves.some((l) => l[0] === t.at_index && l[1] === t.anchor),
          `${t.name}@${cc.cid}: anchor entry`);
      });
    }
  }
  // asynchronous membership checks (UNL end of ledger, PSL status of pledges)
  for (const tp of fx.taxpayers) {
    for (const t of tp.tags) {
      for (let k = 0; k < t.ledgers.length; k++) {
        const led = t.ledgers[k], cc = chains[k];
        ok(!(await cc.unl.has(B(led.nf_next))), `${t.name}@${cc.cid}: NF_{n+1} is a non-member of the pinned UNL`);
        if (led.anchored) ok(await cc.at.has(B(t.at_index)), `${t.name}@${cc.cid}: anchor is in the pinned AT`);
        for (const lr of led.records) {
          const r = cc.ch.records[lr.leaf_index];
          if (B(r.op) !== OP.PLEDGE) continue;
          const closed = cc.ch.psl.entries.some((e) => e.position_id === r.position_id);
          ok((await cc.psl.has(B(r.position_id))) === closed,
            `${t.name}@${cc.cid}: PSL status of position ${r.position_id}`);
        }
      }
    }
  }
  return { n, bad, ledgers, opened, chains: fx.chains.length,
           records: fx.chains.reduce((s, ch) => s + ch.records.length, 0),
           psl: fx.chains.reduce((s, ch) => s + ch.psl.entries.length, 0) };
}

async function main() {
  const c = await init();
  const files = process.argv.length > 2 ? process.argv.slice(2)
    : fs.readdirSync(DIR).filter((f) => f.endsWith(".json")).sort().map((f) => path.join(DIR, f));
  let allGood = true;
  for (const f of files) {
    let r;
    try { r = await checkFile(f, c); }
    catch (e) {      // a malformed file is a failed file, not a crash
      allGood = false;
      console.log(`FAIL  ${path.basename(f).padEnd(18)} could not be checked: ${String(e.message).split("\n")[0]}`);
      continue;
    }
    const good = r.bad.length === 0;
    allGood = allGood && good;
    console.log(`${good ? "PASS" : "FAIL"}  ${path.basename(f).padEnd(18)} ${r.n} checks: ${r.chains} chain(s), ` +
      `${r.records} records, ${r.psl} PSL entries, ${r.ledgers} ledgers opened (${r.opened} records)`);
    for (const b of r.bad) console.log(`      failed: ${b}`);
  }
  console.log(allGood ? "\n== fixtures: all files consistent ==" : "\n== fixtures: FAILED ==");
  process.exit(allGood ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
