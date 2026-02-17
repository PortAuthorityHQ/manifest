#!/usr/bin/env node

"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

const VERSION = require("./package.json").version;
const REPO = "port-authority/manifest";

const PLATFORM_MAP = {
  "darwin-arm64": "manifest-aarch64-apple-darwin.tar.gz",
  "darwin-x64": "manifest-x86_64-apple-darwin.tar.gz",
  "linux-x64": "manifest-x86_64-unknown-linux-gnu.tar.gz",
  "linux-arm64": "manifest-aarch64-unknown-linux-gnu.tar.gz",
};

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;
  return `${platform}-${arch}`;
}

function getDownloadUrl(asset) {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https") ? https.get : http.get;
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Follow redirect
        download(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`Download failed: HTTP ${res.statusCode} from ${url}`));
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

async function main() {
  const platformKey = getPlatformKey();
  const asset = PLATFORM_MAP[platformKey];

  if (!asset) {
    console.error(
      `Unsupported platform: ${platformKey}\n` +
      `Supported: ${Object.keys(PLATFORM_MAP).join(", ")}\n` +
      `Install from source: https://github.com/${REPO}#build-from-source`
    );
    process.exit(1);
  }

  const url = getDownloadUrl(asset);
  const binDir = path.join(__dirname, "bin");
  const binPath = path.join(binDir, "manifest");

  // Skip if binary already exists (e.g., re-running postinstall)
  if (fs.existsSync(binPath)) {
    try {
      execSync(`"${binPath}" --version`, { stdio: "ignore" });
      console.log("manifest binary already installed.");
      return;
    } catch {
      // Binary exists but doesn't work — re-download
    }
  }

  console.log(`Downloading manifest v${VERSION} for ${platformKey}...`);
  console.log(`  ${url}`);

  try {
    const tarball = await download(url);

    // Write tarball to temp file and extract
    const tmpFile = path.join(__dirname, ".manifest-download.tar.gz");
    fs.writeFileSync(tmpFile, tarball);

    fs.mkdirSync(binDir, { recursive: true });
    execSync(`tar xzf "${tmpFile}" -C "${binDir}"`, { stdio: "ignore" });
    fs.unlinkSync(tmpFile);

    // Ensure binary is executable
    fs.chmodSync(binPath, 0o755);

    console.log(`manifest v${VERSION} installed successfully.`);
  } catch (err) {
    console.error(
      `Failed to install manifest: ${err.message}\n` +
      `You can install manually: https://github.com/${REPO}#installation`
    );
    process.exit(1);
  }
}

main();
