// Checks a release before it is uploaded, independently of Tauri (phase 6): the installer's
// signature against the public key in src-tauri/tauri.conf.json, the version the signature was
// made for against latest.json, and latest.json's download URL. Written from the minisign format,
// with Node's own Ed25519 and BLAKE2b, so a bug in Tauri's signing can't hide here. Read-only.
//
// Usage (release.ps1 runs it):  node tools/verify-release.mjs <latest.json> <installer.exe>
// Exit code 0 and "OK" lines when everything checks out; otherwise a "PROBLEM" line and exit 1.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_RELEASES = "https://github.com/SocheatSorng/ByteBroom/releases/download/";

function fail(why) {
  console.log(`PROBLEM: ${why}`);
  process.exit(1);
}

/** The base64 text Tauri stores (pubkey, .sig) decodes to a minisign file: lines of text. */
function minisignLines(b64, what) {
  const text = Buffer.from(b64.trim(), "base64").toString("utf8");
  const lines = text.split("\n").map((l) => l.replace(/\r$/, ""));
  if (!lines[0]?.startsWith("untrusted comment:")) fail(`${what} is not a minisign file`);
  return lines;
}

/** minisign public key: "Ed" + key id (8 bytes) + Ed25519 key (32 bytes). */
function readPublicKey(b64) {
  const raw = Buffer.from(minisignLines(b64, "the public key")[1], "base64");
  if (raw.length !== 42 || raw.subarray(0, 2).toString("latin1") !== "Ed") fail("bad public key");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw.subarray(10)]);
  return { id: raw.subarray(2, 10), key: createPublicKey({ key: spki, format: "der", type: "spki" }) };
}

/** minisign signature: alg (2) + key id (8) + signature (64); trusted comment; global signature. */
function readSignature(b64) {
  const lines = minisignLines(b64, "the signature");
  const raw = Buffer.from(lines[1], "base64");
  if (raw.length !== 74) fail("bad signature length");
  if (!lines[2]?.startsWith("trusted comment: ")) fail("the signature has no trusted comment");
  return {
    alg: raw.subarray(0, 2).toString("latin1"),
    id: raw.subarray(2, 10),
    sig: raw.subarray(10),
    trusted: lines[2].slice("trusted comment: ".length),
    global: Buffer.from(lines[3] ?? "", "base64"),
  };
}

export function check(latest, installer, pubkeyB64) {
  const pk = readPublicKey(pubkeyB64);
  const entry = latest.platforms?.["windows-x86_64"];
  if (!entry) fail("latest.json has no windows-x86_64 entry");
  const s = readSignature(entry.signature);
  if (!s.id.equals(pk.id)) fail("signed by a different key than the one in tauri.conf.json");
  // "ED" signs the BLAKE2b-512 hash of the file (what Tauri uses); "Ed" the file itself.
  let message;
  if (s.alg === "ED") message = createHash("blake2b512").update(installer).digest();
  else if (s.alg === "Ed") message = installer;
  else fail(`unknown signature algorithm ${s.alg}`);
  if (!verify(null, message, pk.key, s.sig)) fail("the installer's signature does not match");
  // The global signature covers the signature and the trusted comment (and so the version).
  const signedComment = Buffer.concat([s.sig, Buffer.from(s.trusted, "utf8")]);
  if (!verify(null, signedComment, pk.key, s.global)) fail("the trusted comment is not signed");
  const signedVersion = s.trusted
    .split("\t")
    .find((f) => f.startsWith("version:"))
    ?.slice("version:".length);
  if (!signedVersion) fail("the signature carries no version (requireSignedVersion would refuse it)");
  if (signedVersion.replace(/^v/, "") !== String(latest.version).replace(/^v/, ""))
    fail(`signed for ${signedVersion}, but latest.json says ${latest.version}`);
  const url = String(entry.url);
  const expected = `${REPO_RELEASES}v${latest.version}/`;
  if (!url.startsWith(expected)) fail(`the download URL must start with ${expected}`);
  return { version: signedVersion, url };
}

if (process.argv[1] && basename(process.argv[1]) === "verify-release.mjs") {
  const [latestPath, installerPath] = process.argv.slice(2);
  if (!latestPath || !installerPath) fail("usage: node tools/verify-release.mjs <latest.json> <installer.exe>");
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const conf = JSON.parse(readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8"));
  const latest = JSON.parse(readFileSync(latestPath, "utf8"));
  const installer = readFileSync(installerPath);
  const { version, url } = check(latest, installer, conf.plugins.updater.pubkey);
  if (!url.endsWith(`/${basename(installerPath)}`)) fail("the download URL names a different file");
  console.log(`OK: ${basename(installerPath)} is signed by ByteBroom's key, for version ${version}.`);
  console.log(`OK: latest.json points at ${url}`);
}
