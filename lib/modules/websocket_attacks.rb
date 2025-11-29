require 'uri'
require 'socket'
require 'openssl'
require 'securerandom'
require_relative '../utils/colorize'

class WebSocketAttacks
  def self.test_websocket(url)
    uri = URI(url)
    host = uri.host
    port = uri.port || (uri.scheme == 'wss' ? 443 : 80)
    
    begin
      socket = TCPSocket.new(host, port)
      
      if uri.scheme == 'wss'
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
        socket.connect
      end
      
      key = SecureRandom.base64(16)
      
      handshake = "GET #{uri.path} HTTP/1.1\r\n"
      handshake += "Host: #{host}:#{port}\r\n"
      handshake += "Upgrade: websocket\r\n"
      handshake += "Connection: Upgrade\r\n"
      handshake += "Sec-WebSocket-Key: #{key}\r\n"
      handshake += "Sec-WebSocket-Version: 13\r\n"
      handshake += "\r\n"
      
      socket.write(handshake)
      response = socket.read(1024)
      
      if response.include?('101 Switching Protocols')
        puts Colorize.green("WebSocket connection established")
        return { connected: true, socket: socket }
      else
        puts Colorize.red("WebSocket connection failed")
        socket.close
        return { connected: false }
      end
    rescue => e
      puts Colorize.red("Error: #{e.message}")
      return { connected: false }
    end
  end

  def self.test_message_injection(socket, message)
    begin
      frame = create_frame(message)
      socket.write(frame)
      response = socket.read(1024)
      return response
    rescue => e
      return nil
    end
  end

  def self.test_cross_site_websocket_hijacking(url, origin)
    uri = URI(url)
    host = uri.host
    port = uri.port || (uri.scheme == 'wss' ? 443 : 80)
    
    begin
      socket = TCPSocket.new(host, port)
      
      if uri.scheme == 'wss'
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
        socket.connect
      end
      
      key = SecureRandom.base64(16)
      
      handshake = "GET #{uri.path} HTTP/1.1\r\n"
      handshake += "Host: #{host}:#{port}\r\n"
      handshake += "Origin: #{origin}\r\n"
      handshake += "Upgrade: websocket\r\n"
      handshake += "Connection: Upgrade\r\n"
      handshake += "Sec-WebSocket-Key: #{key}\r\n"
      handshake += "Sec-WebSocket-Version: 13\r\n"
      handshake += "\r\n"
      
      socket.write(handshake)
      response = socket.read(1024)
      
      if response.include?('101 Switching Protocols')
        puts Colorize.red("CSWSH vulnerability: Origin not validated")
        return { vulnerable: true }
      else
        puts Colorize.green("Origin validation present")
        return { vulnerable: false }
      end
    rescue => e
      return { vulnerable: false }
    end
  end

  def self.test_denial_of_service(url)
    connections = []
    
    100.times do
      result = test_websocket(url)
      if result[:connected]
        connections << result[:socket]
      end
    end
    
    puts Colorize.yellow("Established #{connections.length} connections")
    
    connections.each { |s| s.close rescue nil }
    
    { connections: connections.length }
  end

  private

  def self.create_frame(message)
    bytes = message.bytes
    length = bytes.length
    
    frame = [0x81].pack('C')
    
    if length < 126
      frame += [length].pack('C')
    elsif length < 65536
      frame += [126].pack('C')
      frame += [length].pack('n')
    else
      frame += [127].pack('C')
      frame += [length].pack('Q>')
    end
    
    frame += message
    frame
  end
end

