class Aegis < Formula
  desc "Aegis retro CRT DevSecOps console"
  homepage "https://github.com/huslenine999/aegis"
  url "https://github.com/huslenine999/aegis/archive/refs/tags/v2.0.0.tar.gz"
  head "https://github.com/huslenine999/aegis.git", branch: "main"

  depends_on "python@3.11"

  def install
    libexec.install Dir["*"]
    (bin/"aegis").write <<~EOS
      #!/bin/bash
      exec "#{libexec}/bin/aegis" "$@"
    EOS
  end

  test do
    assert_predicate bin/"aegis", :exist?
  end
end
