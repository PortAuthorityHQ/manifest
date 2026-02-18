class Manifest < Formula
  desc "Cryptographic receipts for AI agent tool calls"
  homepage "https://github.com/PortAuthorityHQ/manifest"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/PortAuthorityHQ/manifest/releases/download/v#{version}/manifest-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end

    on_intel do
      url "https://github.com/PortAuthorityHQ/manifest/releases/download/v#{version}/manifest-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/PortAuthorityHQ/manifest/releases/download/v#{version}/manifest-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end

    on_intel do
      url "https://github.com/PortAuthorityHQ/manifest/releases/download/v#{version}/manifest-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  def install
    bin.install "manifest"
  end

  test do
    system "#{bin}/manifest", "--version"
  end
end
