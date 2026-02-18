#!/usr/bin/env node

"use strict";

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const binPath = path.join(__dirname, "bin", "manifest");

if (!fs.existsSync(binPath)) {
  console.error(
    "manifest binary not found. The postinstall download may have failed.\n" +
    "Try reinstalling: npm install -g @portauthority/manifest\n" +
    "Or install manually: https://github.com/PortAuthorityHQ/manifest#installation"
  );
  process.exit(1);
}

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  process.exit(err.status || 1);
}
