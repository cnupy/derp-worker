// Throwaway keys for tests. The test config allows ALICE, BOB and the Go
// fixture's client; STRANGER is never allowed.

import nacl from "tweetnacl";

export interface TestKey {
  name: string;
  priv: Uint8Array;
  pub: Uint8Array;
  nodekey: string; // "nodekey:<hex>"
}

export const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));

// testKey derives a key pair from a fixed seed byte, so every run uses the
// same keys.
function testKey(name: string, seed: number): TestKey {
  const kp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(seed));
  return { name, priv: kp.secretKey, pub: kp.publicKey, nodekey: `nodekey:${hex(kp.publicKey)}` };
}

export const ALICE = testKey("alice", 1);
export const BOB = testKey("bob", 2);
export const STRANGER = testKey("stranger", 3);

export const STATS_TOKEN = "test-stats-token";
export const STUN_SERVERS = "stun.example.net:3478, stun2.example.net";
