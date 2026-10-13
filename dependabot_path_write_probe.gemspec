require "json"

module F005PathWriteProbe
  module_function

  def attempt(path)
    result = {
      "path" => path,
      "existed_before" => File.exist?(path),
      "created" => false,
      "readback" => false,
      "removed" => false
    }
    return result.merge("error" => "preexisting_target") if result["existed_before"]

    marker = "F005_OWNED_PATH_WRITE_20261013"
    begin
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.write(marker)
      end
      result["created"] = true
      result["readback"] = File.binread(path) == marker
    rescue StandardError => error
      result["error"] = error.class.name
      result["error_errno"] = error.errno if error.respond_to?(:errno)
    ensure
      if result["created"] && File.exist?(path)
        File.delete(path)
        result["removed"] = !File.exist?(path)
      end
    end
    result
  end

  def status_lines
    File.readlines("/proc/self/status", chomp: true).grep(
      /\A(?:Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):/
    )
  rescue StandardError => error
    ["ERROR:#{error.class}"]
  end
end

nonce = Process.pid.to_s
path_entries = ENV.fetch("PATH", "").split(":")
candidate_directory = "/home/dependabot/bin"
candidate_stat = File.stat(candidate_directory)

evidence = {
  "schema" => "F005_PATH_WRITE_V1",
  "uid" => Process.uid,
  "euid" => Process.euid,
  "gid" => Process.gid,
  "egid" => Process.egid,
  "status" => F005PathWriteProbe.status_lines,
  "path" => ENV.fetch("PATH", ""),
  "candidate_path_index" => path_entries.index(candidate_directory),
  "candidate_directory" => {
    "path" => candidate_directory,
    "mode" => format("%04o", candidate_stat.mode & 0o7777),
    "uid" => candidate_stat.uid,
    "gid" => candidate_stat.gid,
    "writable" => File.writable?(candidate_directory)
  },
  "positive_control" => F005PathWriteProbe.attempt("/tmp/f005-owned-positive-control-#{nonce}"),
  "candidate" => F005PathWriteProbe.attempt("#{candidate_directory}/f005-owned-path-canary-#{nonce}"),
  "causal_negative_control" => F005PathWriteProbe.attempt("/usr/bin/f005-owned-negative-control-#{nonce}")
}

raise "F005_PATH_WRITE_HEX=#{JSON.generate(evidence).unpack1("H*")}"
