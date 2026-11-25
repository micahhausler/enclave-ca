class EnclaveCa < Formula
  desc "Offline IAM Roles Anywhere CA with its root key in the Secure Enclave"
  homepage "https://github.com/micahhausler/enclave-ca"
  url "https://github.com/micahhausler/enclave-ca/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "cb8d73123a4c75509e3de47873f304f9a1fba6e881d4b535d44ea7bea789ebd3"
  license "Apache-2.0"
  head "https://github.com/micahhausler/enclave-ca.git", branch: "main"

  depends_on xcode: ["16.0", :build]
  depends_on arch: :arm64
  depends_on macos: :ventura

  def install
    system "swift", "build", "--disable-sandbox", "-c", "release"
    bin.install ".build/release/enclave-ca"
  end

  test do
    assert_equal "enclave-ca #{version}", shell_output("#{bin}/enclave-ca --version").strip
  end
end
