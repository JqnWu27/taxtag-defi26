// Witness generation with the circom-generated wasm calculators in build/.
const fs = require("fs");
const path = require("path");
const Module = require("module");

const BUILD = path.join(__dirname, "..", "build");

// force = true models a prover who ignores failed assertions (what the
// arkworks circom reader inside the fold driver does): a failed `===` is
// counted in calc.failedAsserts instead of throwing, and the calculator still
// returns a (non-satisfying) witness.
async function loadCalculator(name, { force = false } = {}) {
  const dir = path.join(BUILD, `${name}_js`);
  const file = path.join(dir, "witness_calculator.js");
  const wasm = fs.readFileSync(path.join(dir, `${name}.wasm`));
  if (!force) return require(file)(wasm);
  const counter = { n: 0 };
  let src = fs.readFileSync(file, "utf8");
  const needle = "throw new Error(err + errStr);";
  if (!src.includes(needle)) throw new Error("unexpected witness_calculator.js layout");
  src = src.replace(needle,
    "if (code == 4) { globalThis.__taxtagForced.n += 1; errStr = \"\"; return; } " + needle);
  globalThis.__taxtagForced = counter;
  const m = new Module(file + ".forced");
  m.paths = module.paths;
  m._compile(src, file + ".forced.js");
  const calc = await m.exports(wasm);
  Object.defineProperty(calc, "failedAsserts", { get: () => counter.n });
  calc.resetFailed = () => { counter.n = 0; };
  return calc;
}

// returns the witness (BigInt array) or throws if a constraint fails
async function stepWitness(wc, z, ext) {
  return wc.calculateWitness({ ivc_input: [z], external_inputs: ext }, 0);
}

// "Template:line" trace of a circom assert failure, for the test logs. The
// generated calculator accumulates its error text across calls, so only the
// part added by this failure is kept.
const seenErr = new Map();   // per calculator key
function shortErr(e, key = "default") {
  const s = String(e && e.message ? e.message : e);
  const body = s.replace(/^Error: /, "").replace(/^Assert Failed\.\n/, "");
  let fresh = body;
  const prev = seenErr.get(key) || "";
  if (prev && body.startsWith(prev)) fresh = body.slice(prev.length);
  if (body.includes("Error in template")) seenErr.set(key, body);
  const m = fresh.match(/Error in template (\w+)_\d+ line: (\d+)/g);
  return m ? m.map((x) => x.replace("Error in template ", "").replace(" line: ", ":")).join(" < ")
           : s.split("\n")[0];
}

module.exports = { loadCalculator, stepWitness, shortErr, BUILD };
