require 'socket'
require 'net/http'
require 'uri'
require 'timeout'
require 'resolv'

module Network
  def self.port_open?(host, port, timeout = 3)
    Timeout.timeout(timeout) do
      socket = TCPSocket.new(host, port)
      socket.close
      true
    rescue
      false
    end
  rescue
    false
  end

  def self.resolve_host(hostname)
    Resolv.getaddress(hostname) rescue nil
  end

  def self.http_request(url, method = :get, headers = {}, data = nil)
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
    
    req = case method
    when :get then Net::HTTP::Get.new(uri.path)
    when :post then Net::HTTP::Post.new(uri.path)
    when :put then Net::HTTP::Put.new(uri.path)
    when :delete then Net::HTTP::Delete.new(uri.path)
    when :head then Net::HTTP::Head.new(uri.path)
    else Net::HTTP::Get.new(uri.path)
    end
    
    headers.each { |k, v| req[k] = v }
    req.body = data if data
    http.request(req)
  rescue => e
    nil
  end

  def self.banner_grab(host, port)
    socket = TCPSocket.new(host, port)
    socket.puts("HEAD / HTTP/1.0\r\n\r\n")
    banner = socket.read(1024)
    socket.close
    banner
  rescue
    nil
  end
end

