# Homebrew formula for EPMA Windows 11 Creator USB
#
# Homebrew only installs formulae from a tap, so this file must be published to
# a repository named `homebrew-<name>` before it can be used. Once that repo
# exists, users install with:
#
#   brew tap 1985epma/tap
#   brew install epma-windows-usb-creator
#
# Development version, straight from the main branch:
#
#   brew install --HEAD epma-windows-usb-creator
#
# MAINTAINER NOTES
#   * After publishing a new release, refresh `url` and `sha256` by running:
#       ./Formula/update-formula.sh v1.0.0
#   * Validate before publishing:
#       brew style 1985epma/tap
#       brew audit --strict --online 1985epma/tap/epma-windows-usb-creator

class EpmaWindowsUsbCreator < Formula
  desc "Create a bootable Windows 11 USB drive from macOS or Linux"
  homepage "https://github.com/1985epma/epma-windows-usb-creator"
  url "https://github.com/1985epma/epma-windows-usb-creator/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "d836915b03fb2a617e6f27a5c0e18f7b4c158a6a1139f14989f22436660b234a"
  license "GPL-3.0-or-later"
  head "https://github.com/1985epma/epma-windows-usb-creator.git", branch: "main"

  # Tkinter is required for the graphical interface. On macOS, Homebrew ships it
  # as a separate formula from Python itself.
  depends_on "python-tk@3.13"
  depends_on "python@3.13"

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
      exec "#{formula_opt_bin("python@3.13")}/python3.13" "#{libexec}/win11_usb_creator.py" "$@"
    SHELL
    chmod 0755, bin/"epma-windows-usb-creator"
  end

  def caveats
    caveats_text = <<~EOS
      Run the application with:
        epma-windows-usb-creator

      This tool ERASES the selected disk completely. It only ever lists external
      removable drives, requires you to type the disk identifier by hand, and
      re-verifies the target immediately before writing -- but double-check the
      selected disk before confirming.

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
    system formula_opt_bin("python@3.13")/"python3.13", "-c",
           "import sys, pathlib; p = pathlib.Path(sys.argv[1]); " \
           "compile(p.read_text(encoding='utf-8'), str(p), 'exec')",
           libexec/"win11_usb_creator.py"
    assert_predicate bin/"epma-windows-usb-creator", :executable?

    # Confirm Tkinter is importable under the Python this formula depends on --
    # this is the single most common installation failure for the application.
    system formula_opt_bin("python@3.13")/"python3.13", "-c", "import tkinter"
  end
end
