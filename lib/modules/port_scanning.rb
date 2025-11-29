require 'socket'
require 'timeout'
require_relative '../utils/network'
require_relative '../utils/colorize'

class PortScanning
  def self.stealth_scan(host, ports, timeout = 3)
    open_ports = []
    
    ports.each do |port|
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        sockaddr = Socket.sockaddr_in(port, host)
        
        begin
          socket.connect_nonblock(sockaddr)
          open_ports << port
          puts Colorize.green("Port #{port} open")
        rescue Errno::EINPROGRESS
          if IO.select(nil, [socket], nil, timeout)
            begin
              socket.connect_nonblock(sockaddr)
              open_ports << port
              puts Colorize.green("Port #{port} open")
            rescue Errno::EISCONN
              open_ports << port
              puts Colorize.green("Port #{port} open")
            rescue
            end
          end
        rescue
        end
        
        socket.close
      rescue
      end
    end
    
    open_ports
  end

  def self.fin_scan(host, ports)
    open_ports = []
    
    ports.each do |port|
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        sockaddr = Socket.sockaddr_in(port, host)
        socket.connect(sockaddr)
        socket.send("", Socket::MSG_OOB)
        socket.close
        open_ports << port
        puts Colorize.green("Port #{port} open (FIN scan)")
      rescue
      end
    end
    
    open_ports
  end

  def self.xmas_scan(host, ports)
    open_ports = []
    
    ports.each do |port|
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        sockaddr = Socket.sockaddr_in(port, host)
        socket.connect(sockaddr)
        socket.send("", Socket::MSG_OOB | Socket::MSG_DONTROUTE)
        socket.close
        open_ports << port
        puts Colorize.green("Port #{port} open (XMAS scan)")
      rescue
      end
    end
    
    open_ports
  end

  def self.null_scan(host, ports)
    open_ports = []
    
    ports.each do |port|
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        sockaddr = Socket.sockaddr_in(port, host)
        socket.connect(sockaddr)
        socket.send("", 0)
        socket.close
        open_ports << port
        puts Colorize.green("Port #{port} open (NULL scan)")
      rescue
      end
    end
    
    open_ports
  end

  def self.udp_scan(host, ports)
    open_ports = []
    
    ports.each do |port|
      begin
        socket = UDPSocket.new
        socket.send("test", 0, host, port)
        socket.close
        open_ports << port
        puts Colorize.green("Port #{port} open (UDP)")
      rescue
      end
    end
    
    open_ports
  end

  def self.version_detection(host, port)
    begin
      banner = Network.banner_grab(host, port)
      return nil unless banner
      
      version_info = {
        port: port,
        banner: banner,
        service: detect_service(port, banner)
      }
      
      version_info
    rescue
      nil
    end
  end

  def self.detect_service(port, banner)
    services = {
      21 => 'FTP',
      22 => 'SSH',
      23 => 'Telnet',
      25 => 'SMTP',
      53 => 'DNS',
      80 => 'HTTP',
      110 => 'POP3',
      143 => 'IMAP',
      443 => 'HTTPS',
      445 => 'SMB',
      3306 => 'MySQL',
      3389 => 'RDP',
      5432 => 'PostgreSQL',
      5900 => 'VNC',
      8080 => 'HTTP-Proxy'
    }
    
    service = services[port]
    
    if banner
      banner_lower = banner.downcase
      if banner_lower.include?('apache')
        service = 'Apache HTTP Server'
      elsif banner_lower.include?('nginx')
        service = 'Nginx'
      elsif banner_lower.include?('iis')
        service = 'IIS'
      elsif banner_lower.include?('mysql')
        service = 'MySQL'
      elsif banner_lower.include?('postgres')
        service = 'PostgreSQL'
      elsif banner_lower.include?('ssh')
        service = 'SSH'
      end
    end
    
    service || 'Unknown'
  end
end

