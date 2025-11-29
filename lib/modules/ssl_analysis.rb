require 'openssl'
require 'socket'
require_relative '../utils/colorize'

class SSLAnalysis
  def self.check_certificate(host, port = 443)
    begin
      context = OpenSSL::SSL::SSLContext.new
      tcp_socket = TCPSocket.new(host, port)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
      ssl_socket.connect
      cert = ssl_socket.peer_cert
      
      result = {
        subject: cert.subject.to_s,
        issuer: cert.issuer.to_s,
        not_before: cert.not_before,
        not_after: cert.not_after,
        expired: cert.not_after < Time.now,
        days_left: cert.not_after < Time.now ? 0 : ((cert.not_after - Time.now) / 86400).to_i
      }
      
      ssl_socket.close
      tcp_socket.close
      result
    rescue => e
      nil
    end
  end

  def self.analyze_protocols(host, port = 443)
    protocols = {
      'SSLv2' => OpenSSL::SSL::SSL2_VERSION,
      'SSLv3' => OpenSSL::SSL::SSL3_VERSION,
      'TLSv1' => OpenSSL::SSL::TLS1_VERSION,
      'TLSv1.1' => OpenSSL::SSL::TLS1_1_VERSION,
      'TLSv1.2' => OpenSSL::SSL::TLS1_2_VERSION
    }
    
    supported = {}
    protocols.each do |name, version|
      begin
        context = OpenSSL::SSL::SSLContext.new
        context.min_version = version
        context.max_version = version
        tcp_socket = TCPSocket.new(host, port)
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
        ssl_socket.connect
        supported[name] = true
        ssl_socket.close
        tcp_socket.close
      rescue
        supported[name] = false
      end
    end
    
    supported
  end

  def self.check_heartbleed(host, port = 443)
    begin
      context = OpenSSL::SSL::SSLContext.new
      tcp_socket = TCPSocket.new(host, port)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
      ssl_socket.connect
      ssl_socket.close
      tcp_socket.close
      false
    rescue
      false
    end
  end
end

