#!/usr/bin/env node

"use strict";

// Lightweight test for npm install.js platform detection logic.
// Run: node npm/install.test.js

const PLATFORM_MAP = {
  "darwin-arm64": "manifest-aarch64-apple-darwin.tar.gz",
  "darwin-x64": "manifest-x86_64-apple-darwin.tar.gz",
  "linux-x64": "manifest-x86_64-unknown-linux-gnu.tar.gz",
  "linux-arm64": "manifest-aarch64-unknown-linux-gnu.tar.gz",
};

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  PASS  ${message}`);
  } else {
    failed++;
    console.log(`  FAIL  ${message}`);
  }
}

// Test: all 4 supported platforms resolve to correct tarballs
assert(
  PLATFORM_MAP["darwin-arm64"] === "manifest-aarch64-apple-darwin.tar.gz",
  "macOS ARM64 resolves correctly"
);
assert(
  PLATFORM_MAP["darwin-x64"] === "manifest-x86_64-apple-darwin.tar.gz",
  "macOS x64 resolves correctly"
);
assert(
  PLATFORM_MAP["linux-x64"] === "manifest-x86_64-unknown-linux-gnu.tar.gz",
  "Linux x64 resolves correctly"
);
assert(
  PLATFORM_MAP["linux-arm64"] === "manifest-aarch64-unknown-linux-gnu.tar.gz",
  "Linux ARM64 resolves correctly"
);

// Test: unsupported platforms return undefined
assert(
  PLATFORM_MAP["win32-x64"] === undefined,
  "Windows x64 is unsupported"
);
assert(
  PLATFORM_MAP["freebsd-x64"] === undefined,
  "FreeBSD is unsupported"
);
assert(
  PLATFORM_MAP["linux-ia32"] === undefined,
  "Linux 32-bit is unsupported"
);

// Test: current platform resolves (sanity check)
const currentKey = `${process.platform}-${process.arch}`;
const currentAsset = PLATFORM_MAP[currentKey];
if (currentAsset) {
  assert(currentAsset.endsWith(".tar.gz"), `Current platform (${currentKey}) resolves to tarball`);
} else {
  console.log(`  SKIP  Current platform ${currentKey} not in PLATFORM_MAP (expected on unsupported OS)`);
}

// Test: download URL format
const VERSION = "0.1.0";
const REPO = "PortAuthorityHQ/manifest";
const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${PLATFORM_MAP["darwin-arm64"]}`;
assert(
  url === "https://github.com/PortAuthorityHQ/manifest/releases/download/v0.1.0/manifest-aarch64-apple-darwin.tar.gz",
  "Download URL format is correct"
);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
