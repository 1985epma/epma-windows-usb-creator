# Homebrew formula for EPMA USB CREATOR
#
# Homebrew only installs formulae from a tap, so this file is published to
# https://github.com/1985epma/homebrew-tap. Users install with:
#
#   brew tap 1985epma/tap
#   brew trust 1985epma/tap        # required for third-party taps
#   brew install epma-windows-usb-creator
#
# Development version, straight from the main branch:
#
#   brew install --HEAD epma-windows-usb-creator
#
# MAINTAINER NOTES
#   * Publishing a release (tag v*) updates the tap AUTOMATICALLY: the "Homebrew tap"
#     workflow runs ./Formula/update-formula.sh for the tag and opens a pull request
#     on 1985epma/homebrew-tap (needs the repository secret TAP_GITHUB_TOKEN).
#   * To do it by hand, refresh `url` and `sha256` by running:
#       ./Formula/update-formula.sh v1.1.0
#   * Validate before publishing:
#       brew style 1985epma/tap
#       brew audit --strict --online 1985epma/tap/epma-windows-usb-creator

class EpmaWindowsUsbCreator < Formula
  desc "Create verified bootable USB drives from Windows 11, Linux and ChromeOS Flex"
  homepage "https://github.com/1985epma/epma-windows-usb-creator"
  url "https://github.com/1985epma/epma-windows-usb-creator/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "644ae570a194e1915562b14b7760a9e2a6407e1c253647582c6e67cb93197583"
  license "GPL-3.0-or-later"
  head "https://github.com/1985epma/epma-windows-usb-creator.git", branch: "main"

  # The program is written in Rust and built from source with the toolchain Homebrew provides.
  depends_on "rust" => :build

  # Required to split install.wim/install.esd when it exceeds the FAT32 4 GB
  # single-file limit, which is the case for every current Windows 11 image.
  depends_on "wimlib"

  def install
    # `--locked`: build exactly the dependency versions recorded in Cargo.lock.
    system "cargo", "install", "--locked", *std_cargo_args
    libexec.install "SECURITY.md", "README.md", "LICENSE"

    # Long name used by the Homebrew formula; the binary itself is epma-usb-creator,
    # the name shown in the macOS menu bar.
    bin.install_symlink "epma-usb-creator" => "epma-windows-usb-creator"
  end

  def caveats
    caveats_text = <<~EOS
      Run the application with:
        epma-windows-usb-creator

      This tool ERASES the selected disk completely. Safeguards built in:
        * only USB drives are listed -- never your internal disk;
        * a final confirmation dialog names the drive before anything is erased
          (for high-risk disks you must also type the disk identifier);
        * the target is re-verified immediately before writing;
        * afterwards the drive is read back and compared with the image, and it
          is ejected only if that verification passes.
      Please still double-check the selected disk before confirming.

      The administrator password is asked for once, up front, before the drive
      is touched. It is used only to run local disk commands and is never logged,
      written to disk or sent anywhere.

      Always download the Windows image from Microsoft's official website. The
      application accepts HTTPS links only and warns about unrecognised servers,
      but it cannot verify authenticity on your behalf unless you supply the
      expected SHA-256 checksum.

      Security documentation:
        #{libexec}/SECURITY.md
    EOS

    on_linux do
      caveats_text += <<~EOS

        On Linux, the following tools must be installed through your distribution's
        package manager (they are not provided by Homebrew):
          parted, dosfstools (mkfs.vfat), util-linux (wipefs), rsync

        Debian/Ubuntu:
          sudo apt install parted dosfstools util-linux rsync

        Writing to a raw block device requires root, so the application will ask
        for your administrator password.
      EOS
    end

    caveats_text
  end

  test do
    # A GUI application cannot be launched in a test environment, so check the
    # command line: it must start, name itself and list its commands.
    assert_match "write", shell_output("#{bin}/epma-usb-creator --help")
    assert_match(/\d+\.\d+\.\d+/, shell_output("#{bin}/epma-usb-creator --version"))
    assert_predicate bin/"epma-windows-usb-creator", :executable?
  end
end
