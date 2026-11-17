// Fixture writer: everything the filing side needs to open the ledgers a
// scenario produced. Schema documented in fixtures/README.md.
// All field elements and 64-bit quantities are decimal strings.
const fs = require("fs");
const path = require("path");
const { PARAMS } = require("./hashes");
const { evaluate, emptyState } = require("./rule_ref");

const ROOT = path.resolve(__dirname, "..", "..");
const SCHEMA = "taxtag-recording-fixture/1";

const ser = (v) => {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(ser);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = ser(x);
    return o;
  }
  return v;
};

const RECORD_FIELDS = ["leaf_index", "leaf", "nf", "cid", "block", "idx", "time", "op",
  "asset_in", "amount_in", "asset_out", "amount_out", "value", "position_id",
  "meta", "body", "tail"];
const PSL_FIELDS = ["position_id", "kind", "cid", "block", "idx", "time",
  "asset_a", "amount_a", "asset_b", "amount_b", "value", "pmeta", "pbody", "pentry"];
const pick = (o, ks) => Object.fromEntries(ks.map((k) => [k, o[k]]));

function chainBlock(w) {
  const m = w.m;
  return {
    cid: w.cid,
    acaddr: w.acaddr,
    acaddr_hex: w.acaddrHex,
    keyset_digest: w.c.keysetDigest,
    assets: w.assets,
    contracts: w.contracts,
    rcl: { depth: PARAMS.DR, empty_leaf: 0n, root: m.rcl.root(), leaves: m.rcl.leaves },
    records: m.records.map((r) => ({
      ...pick(r, RECORD_FIELDS),
      // no transaction hash: it covers the randomized proof and would
      // change on every run, the rest of the file is reproducible byte for byte
      test_only: { tag: r.tag, i: r.i, label: r.label, owner: r.owner,
                   cited_root_rcl: r.cited_root_rcl },
    })),
    nf_log: m.nfLog,
    unl: { covered: m.unlCovered, root: m.unl.root(), leaves: m.unl.leaves },
    at: { root: m.at.root(), leaves: m.at.leaves },
    trl: { root: m.trl.root(), leaves: m.trl.leaves },
    psl: { root: m.psl.root(),
           entries: m.passive.map((e) => ({ ...pick(e, PSL_FIELDS),
                                            test_only: { label: e.label } })) },
    snapshots: m.snapshots,
  };
}

// taxpayers: [{ name, role, tags: [tagObj, ...] }]; worlds: [World, ...]
function taxpayerBlock(tp, worlds) {
  return {
    name: tp.name,
    address: worlds[0].addr[tp.role],
    tags: tp.tags.map((t) => ({
      name: t.name, tag: t.tag, S: t.S,
      id_tax: t.idTax, anchor: t.anchor, at_index: t.atKey,
      ta_key_index: t.taIndex,
      credential: { R8x: t.sig.R8x, R8y: t.sig.R8y, S: t.sig.S },
      ledgers: worlds.map((w) => {
        const led = w.ledgers.get(t.name) || [];
        return {
          cid: w.cid, acaddr: w.acaddr,
          anchored: w.m.at.leaves.some(([k]) => k === t.atKey),
          records: led.map((r) => ({ i: r.i, nf: r.nf, leaf_index: r.leaf_index })),
          next_counter: led.length + 1,
          nf_next: w.H.nullifier(t.idTax, w.cid, w.acaddr, BigInt(led.length + 1)),
        };
      }),
    })),
  };
}

// Reference rule evaluation per pinned period for one taxpayer (informative).
// Every chain must have pinned the same list of periods.
function expectedBlock(tp, worlds) {
  const periods = worlds[0].m.snapshots.map((s) => s.period);
  const names = new Set(tp.tags.map((t) => t.name));
  let state = emptyState();
  const out = [];
  for (let p = 0; p < periods.length; p++) {
    let records = [], passive = [];
    for (const w of worlds) {
      const snap = w.m.snapshots[p];
      const prev = p > 0 ? w.m.snapshots[p - 1] : { leaf_count: 0, psl_count: 0 };
      if (snap.period !== periods[p]) throw new Error("chains pinned different periods");
      records = records.concat(w.m.records.filter((r) => names.has(r.tag) &&
        r.leaf_index >= prev.leaf_count && r.leaf_index < snap.leaf_count));
      passive = passive.concat(w.m.passive.slice(prev.psl_count, snap.psl_count));
    }
    const res = evaluate(state, records, passive);
    out.push({
      period: periods[p],
      start_state: state,
      D: res.D,
      income_parts: res.parts,
      closing_state: res.closing,
      merged_sequence: res.sequence,
      integer_average_exact: res.exact,
    });
    state = res.closing;
  }
  return out;
}

function writeFixture(name, { scenario, worlds, taxpayers, notes }) {
  const fx = {
    schema: SCHEMA,
    scenario: name,
    description: scenario,
    hash: "Poseidon over BN254 (circomlib parameters); see SPEC.md section 2",
    params: { smt_depth: PARAMS.D, rcl_depth: PARAMS.DR, ta_keys: PARAMS.NKEYS },
    units: {
      amounts: "integers in token units: USDC 1 unit = 1 USDC, ETH 1 unit = 0.01 ETH",
      value: "integer USD (mock oracle), value = amount * price per token unit",
      time: "block timestamp, seconds since the Unix epoch",
    },
    keyset: { pubx: worlds[0].c.pubx, puby: worlds[0].c.puby, digest: worlds[0].c.keysetDigest },
    chains: worlds.map(chainBlock),
    taxpayers: taxpayers.map((tp) => taxpayerBlock(tp, worlds)),
    expected: taxpayers.filter((tp) => tp.expected !== false).map((tp) => ({
      taxpayer: tp.name,
      note: "informative: reference moving-average evaluation by harness/lib/rule_ref.js, not the filing circuit",
      filings: expectedBlock(tp, worlds),
    })),
    notes: notes || [],
  };
  const dir = path.join(ROOT, "fixtures");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name + ".json");
  fs.writeFileSync(file, JSON.stringify(ser(fx), null, 1) + "\n");
  return { file, fixture: ser(fx) };
}

module.exports = { writeFixture, expectedBlock, ser, SCHEMA };
