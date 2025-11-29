require_relative '../utils/network'
require_relative '../utils/colorize'

class Scanner
  def initialize(host, options = {})
    @host = host
    @timeout = options[:timeout] || 3
    @threads = options[:threads] || 50
  end

  def port_scan(ports)
    open_ports = []
    ports.each_slice(@threads) do |batch|
      threads = batch.map do |port|
        Thread.new do
          if Network.port_open?(@host, port, @timeout)
            open_ports << port
            puts Colorize.green("Port #{port} open")
          end
        end
      end
      threads.each(&:join)
    end
    open_ports
  end

  def service_scan(ports)
    services = {
      21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
      53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP',
      443 => 'HTTPS', 445 => 'SMB', 3306 => 'MySQL', 3389 => 'RDP',
      5432 => 'PostgreSQL', 5900 => 'VNC', 8080 => 'HTTP-Proxy',
      27017 => 'MongoDB', 6379 => 'Redis', 9200 => 'Elasticsearch'
    }
    
    ports.map do |port|
      service = services[port] || Network.banner_grab(@host, port)
      { port: port, service: service || 'Unknown' }
    end
  end
end

