require "fcntl"
require "json"

module F005FdInventory
  module_function

  def safe_read(path, limit = 16_384)
    File.binread(path, limit)
  rescue StandardError => error
    "ERROR:#{error.class}"
  end

  def safe_link(path)
    File.readlink(path)
  rescue StandardError => error
    "ERROR:#{error.class}"
  end

  def descriptor_inventory
    Dir.open("/proc/self/fd") do |directory|
      directory_fd = directory.fileno
      ids = directory.each_child.grep(/\A\d+\z/).map(&:to_i).sort.first(64)
      ids.reject { |fd| fd == directory_fd }.map { |fd| descriptor(fd) }
    end
  rescue StandardError
    []
  end

  def descriptor(fd)
    path = "/proc/self/fd/#{fd}"
    stat = File.stat(path)
    io = IO.for_fd(fd, autoclose: false)
    flags = io.fcntl(Fcntl::F_GETFD)
    {
      "fd" => fd,
      "target" => safe_link(path),
      "type" => stat.ftype,
      "mode" => format("%o", stat.mode & 0o7777),
      "uid" => stat.uid,
      "gid" => stat.gid,
      "device" => stat.dev,
      "inode" => stat.ino,
      "size" => stat.size,
      "close_on_exec" => (flags & Fcntl::FD_CLOEXEC) != 0,
      "fdinfo" => safe_read("/proc/self/fdinfo/#{fd}", 2048).lines.first(16).map(&:strip)
    }
  rescue StandardError => error
    {"fd" => fd, "error" => error.class.name}
  end

  def socket_tables
    %w[/proc/net/unix /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6].to_h do |path|
      [path, safe_read(path, 65_536).lines.first(256).map(&:strip)]
    end
  end
end

baseline_descriptors = F005FdInventory.descriptor_inventory
baseline_ids = baseline_descriptors.filter_map do |descriptor|
  descriptor["fd"] unless descriptor.key?("error")
end
pipe_reader, pipe_writer = IO.pipe
positive_ids = [pipe_reader.fileno, pipe_writer.fileno]
after_pipe_descriptors = F005FdInventory.descriptor_inventory
after_pipe_ids = after_pipe_descriptors.filter_map do |descriptor|
  descriptor["fd"] unless descriptor.key?("error")
end

evidence = {
  "schema" => "F005_FD_INVENTORY_V1",
  "job_id" => ENV.fetch("DEPENDABOT_JOB_ID", "unknown"),
  "process" => {
    "pid" => Process.pid,
    "ppid" => Process.ppid,
    "uid" => Process.uid,
    "euid" => Process.euid,
    "gid" => Process.gid,
    "egid" => Process.egid
  },
  "baseline_ids" => baseline_ids,
  "nonstdio_baseline_ids" => baseline_ids.reject { |fd| fd <= 2 },
  "positive_control_pipe_ids" => positive_ids,
  "positive_control_visible" => positive_ids.all? { |fd| after_pipe_ids.include?(fd) },
  "baseline_descriptors" => baseline_descriptors,
  "after_pipe_descriptors" => after_pipe_descriptors,
  "socket_tables" => F005FdInventory.socket_tables
}

pipe_reader.close
pipe_writer.close

encoded = JSON.generate(evidence).unpack1("H*")
raise "F005_FD_INVENTORY_V1_JSON_HEX=#{encoded}"

Gem::Specification.new do |spec|
  spec.name = "dependabot-fd-inventory-probe"
  spec.version = "0.0.1"
  spec.summary = "Owned Dependabot inherited descriptor inventory"
  spec.authors = ["Mrunal Chawda"]
  spec.files = []
  spec.require_paths = ["lib"]
end
