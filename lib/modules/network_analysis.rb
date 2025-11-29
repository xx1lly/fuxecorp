require 'socket'
require 'timeout'
require 'resolv'
require_relative '../utils/network'
require_relative '../utils/colorize'

class NetworkAnalysis
  def self.ping_sweep(network)
    results = []
    ip_base = network.split('/')[0]
    cidr = network.split('/')[1].to_i
    
    total_hosts = 2**(32 - cidr)
    start_ip = ip_to_int(ip_base)
    
    total_hosts.times do |i|
      ip = int_to_ip(start_ip + i)
      if ping_host(ip)
        puts Colorize.green("Host alive: #{ip}")
        results << ip
      end
    end
    
    results
  end

  def self.traceroute(host, max_hops = 30)
    results = []
    
    (1..max_hops).each do |ttl|
      begin
        socket = UDPSocket.new
        socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)
        socket.send("test", 0, host, 33434)
        
        begin
          Timeout.timeout(3) do
            data, addr = socket.recvfrom(1024)
            results << { hop: ttl, ip: addr[3] }
            break if addr[3] == host
          end
        rescue Timeout::Error
          results << { hop: ttl, ip: "*" }
        end
        
        socket.close
      rescue
        results << { hop: ttl, ip: "*" }
      end
    end
    
    results
  end

  def self.analyze_traffic(host, port, duration = 10)
    start_time = Time.now
    packets = 0
    bytes = 0
    
    begin
      socket = TCPSocket.new(host, port)
      
      while Time.now - start_time < duration
        begin
          data = socket.read_nonblock(1024)
          packets += 1
          bytes += data.length
        rescue IO::WaitReadable
          sleep(0.1)
        end
      end
      
      socket.close
    rescue
    end
    
    {
      packets: packets,
      bytes: bytes,
      duration: Time.now - start_time,
      packets_per_second: packets / duration,
      bytes_per_second: bytes / duration
    }
  end

  def self.detect_firewall(host, ports = [80, 443, 22, 21, 25, 53])
    results = {}
    
    ports.each do |port|
      begin
        socket = TCPSocket.new(host, port)
        socket.close
        results[port] = { status: "open", firewall: false }
      rescue Errno::ECONNREFUSED
        results[port] = { status: "closed", firewall: false }
      rescue Errno::ETIMEDOUT
        results[port] = { status: "filtered", firewall: true }
      rescue
        results[port] = { status: "unknown", firewall: nil }
      end
    end
    
    results
  end

  def self.analyze_dns(domain)
    results = {
      a: [],
      aaaa: [],
      mx: [],
      ns: [],
      txt: [],
      cname: []
    }
    
    begin
      Resolv::DNS.open do |dns|
        results[:a] = dns.getresources(domain, Resolv::DNS::Resource::IN::A).map(&:address)
        results[:aaaa] = dns.getresources(domain, Resolv::DNS::Resource::IN::AAAA).map(&:address)
        results[:mx] = dns.getresources(domain, Resolv::DNS::Resource::IN::MX).map { |r| "#{r.preference} #{r.exchange}" }
        results[:ns] = dns.getresources(domain, Resolv::DNS::Resource::IN::NS).map(&:name)
        results[:txt] = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT).map(&:strings).flatten
        results[:cname] = dns.getresources(domain, Resolv::DNS::Resource::IN::CNAME).map(&:name)
      end
    rescue
    end
    
    results
  end

  def self.detect_cdn(domain)
    cdn_indicators = {
      'cloudflare' => ['cloudflare.com', 'cf-ray'],
      'akamai' => ['akamai.net', 'akamaihd.net'],
      'fastly' => ['fastly.com', 'fastly.net'],
      'maxcdn' => ['maxcdn.com'],
      'incapsula' => ['incapsula.com'],
      'keycdn' => ['keycdn.com']
    }
    
    results = analyze_dns(domain)
    detected = []
    
    results[:cname].each do |cname|
      cdn_indicators.each do |cdn, indicators|
        indicators.each do |indicator|
          if cname.to_s.include?(indicator)
            detected << cdn
          end
        end
      end
    end
    
    detected.uniq
  end

  private

  def self.ping_host(ip)
    begin
      result = `ping -n 1 -w 1000 #{ip}` rescue `ping -c 1 -W 1 #{ip}`
      result.include?("TTL") || result.include?("ttl")
    rescue
      false
    end
  end

  def self.ip_to_int(ip)
    ip.split('.').map(&:to_i).pack('C*').unpack('N*')[0]
  end

  def self.int_to_ip(int)
    [int].pack('N*').unpack('C*').join('.')
  end
end

