import { encode as encodeToHex } from "https://deno.land/std@0.171.0/encoding/hex.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iterations = 10000; // number of iterations
const keyLength = 128; // length of key in bits

/**
 * Takes a string or Uint8Array and hashes it with PBKDF2 using the the
 * Web Crypto API and returns a hex string.
 */
export async function createHash(
  password: string | Uint8Array,
): Promise<string> {
  const encodedPassword = typeof password === "string"
    ? encoder.encode(password)
    : password;
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encodedPassword,
    { name: "PBKDF2" },
    false,
    // deriveBits is obsolete: https://github.com/denoland/deno/issues/14693
    ["deriveKey", "deriveBits"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt,
      "iterations": iterations,
      "hash": "SHA-256",
    },
    baseKey,
    { "name": "AES-GCM", "length": keyLength },
    true,
    ["encrypt", "decrypt"],
  );
  const keyData = await crypto.subtle.exportKey("raw", key);
  const passwordHash = new Uint8Array(keyData);
  return decoder.decode(encodeToHex(passwordHash));
}
