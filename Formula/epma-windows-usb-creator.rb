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

  # Tkinter is required for the graphical interface. On macOS, Homebrew ships it
  # as a separate formula from Python itself.
  depends_on "python-tk@3.15"
  depends_on "python@3.15"

  # Required to split install.wim/install.esd when it exceeds the FAT32 4 GB
  # single-file limit, which is the case for every current Windows 11 image.
  depends_on "wimlib"

  def install
    libexec.install "win11_usb_creator.py"
    libexec.install "SECURITY.md", "README.md", "LICENSE"

    # A wrapper is used instead of a symlink so the application always runs
    # under the Python that Homebrew installed Tkinter for.
    (bin/"epma-windows-usb-creator").write <<~SHELL
      #!/bin/bash
      exec "#{formula_opt_bin("python@3.15")}/python3.15" "#{libexec}/win11_usb_creator.py" "$@"
    SHELL
    chmod 0755, bin/"epma-windows-usb-creator"
    # Short name that matches the application name shown in the macOS menu bar.
    bin.install_symlink "epma-windows-usb-creator" => "epma-usb-creator"
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
    # A GUI application cannot be launched in a test environment, so verify the
    # installed script is syntactically valid and that its wrapper is executable.
    #
    # `compile()` is used instead of `py_compile` because the latter writes a
    # __pycache__ directory next to the source, and the Cellar is read-only here.
    system formula_opt_bin("python@3.15")/"python3.15", "-c",
           "import sys, pathlib; p = pathlib.Path(sys.argv[1]); " \
           "compile(p.read_text(encoding='utf-8'), str(p), 'exec')",
           libexec/"win11_usb_creator.py"
    assert_predicate bin/"epma-windows-usb-creator", :executable?

    # Confirm Tkinter is importable under the Python this formula depends on --
    # this is the single most common installation failure for the application.
    system formula_opt_bin("python@3.15")/"python3.15", "-c", "import tkinter"
  end
end
