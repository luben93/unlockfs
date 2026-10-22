# Template for a Homebrew tap (https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap):
# put this file at Formula/unlockfs.rb in a repo named homebrew-<tap>, fill in url and sha256 after tagging a release.
class Unlockfs < Formula
  desc "Read-only FUSE filesystem serving encrypted files behind a Touch ID prompt, asked once"
  homepage "https://github.com/luben93/unlockfs"
  url "https://github.com/luben93/unlockfs/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_OF_THE_TARBALL"
  license "MIT"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}"), "./cmd/unlockfs"
  end

  def caveats
    <<~EOS
      unlockfs needs FUSE-T (headers at build time, library at run time):
        brew install --cask macos-fuse-t/homebrew-cask/fuse-t
      Start it at login with the launchd agent from contrib/install-launchd.sh in the source tree.
    EOS
  end

  test do
    assert_match "unlockfs", shell_output("#{bin}/unlockfs version")
  end
end
