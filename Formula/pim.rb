class Pim < Formula
  repo_path = File.expand_path("..", File.dirname(__FILE__))
  repo_url = `git -C '#{repo_path}' remote get-url origin`.chomp.strip
  commit_count = `git -C '#{repo_path}' rev-list --count HEAD`.chomp.strip

  # Get latest tag, fallback to commit count
  latest_tag = `git -C '#{repo_path}' describe --tags --abbrev=0 2>/dev/null`.chomp.strip
  version_str = latest_tag.empty? ? "1.0.#{commit_count}" : latest_tag.sub(/^v/, '')

  desc "Interactive CLI tool for managing Azure PIM role activations"
  url "file://#{repo_path}", using: :git, branch: "main"
  head repo_url, using: :git, branch: "main"
  version version_str
  license "MIT"

  depends_on "go" => :build
  depends_on "azure-cli"

  def install
    system "go", "build", "-o", "pim", "./cmd/pim"
    bin.install "pim"
  end

  test do
    assert_match "Azure PIM Activator", shell_output("#{bin}/pim --help")
  end
end
