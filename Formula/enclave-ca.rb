class EnclaveCa < Formula
  desc "Offline IAM Roles Anywhere CA with its root key in the Secure Enclave"
  homepage "https://github.com/micahhausler/enclave-ca"
  url "https://github.com/micahhausler/enclave-ca/releases/download/v0.1.1/enclave-ca-0.1.1.tar.gz"
  sha256 "2080be05d9f6a09ef3848111f10a2bcd8fc58f7d73b56d31cfe911cf33f9ff44"
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
