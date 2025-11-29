require 'net/http'
require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class IoTAttacks
  def self.scan_iot_devices(network_range)
    script = <<~SH
      #!/bin/bash
      
      RANGE="#{network_range}"
      
      for ip in $(seq 1 254); do
          host="$RANGE.$ip"
          ping -c 1 -W 1 $host > /dev/null 2>&1
          if [ $? -eq 0 ]; then
              echo "Found: $host"
              nmap -p 80,443,8080,8443,1883,8883 $host
          fi
      done
    SH
    
    filename = "iot_scan_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("IoT scan script saved: #{filename}")
    filename
  end

  def self.test_default_credentials_iot(ip, port = 80)
    credentials = [
      { user: 'admin', pass: 'admin' },
      { user: 'admin', pass: '' },
      { user: 'root', pass: 'root' },
      { user: 'root', pass: '' },
      { user: 'admin', pass: 'password' },
      { user: 'admin', pass: '123456' },
      { user: 'user', pass: 'user' },
      { user: 'guest', pass: 'guest' }
    ]
    
    results = []
    
    credentials.each do |cred|
      begin
        uri = URI("http://#{ip}:#{port}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.read_timeout = 3
        
        req = Net::HTTP::Get.new('/')
        req.basic_auth(cred[:user], cred[:pass])
        
        res = http.request(req)
        
        if res.code.to_i != 401
          puts Colorize.red("Default credentials work: #{cred[:user]}:#{cred[:pass]}")
          results << { credentials: cred, accessible: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_mqtt_unauthorized(ip, port = 1883)
    begin
      require 'socket'
      socket = TCPSocket.new(ip, port)
      
      connect_packet = [
        0x10,
        0x0e,
        0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
        0x04,
        0x02,
        0x00, 0x3c,
        0x00, 0x04, 0x74, 0x65, 0x73, 0x74
      ].pack('C*')
      
      socket.write(connect_packet)
      response = socket.read(4)
      socket.close
      
      if response && response.bytes[0] == 0x20
        puts Colorize.red("MQTT unauthorized access possible")
        return { vulnerable: true }
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.test_telnet_access(ip, port = 23)
    begin
      require 'net/telnet' rescue nil
      if defined?(Net::Telnet)
        telnet = Net::Telnet.new(
          'Host' => ip,
          'Port' => port,
          'Timeout' => 3
        )
        
        telnet.login('admin', 'admin') rescue nil
        telnet.close
        
        puts Colorize.yellow("Telnet accessible on #{ip}:#{port}")
        return { accessible: true }
      else
        puts Colorize.yellow("Telnet library not available")
        return { accessible: false }
      end
    rescue => e
      return { accessible: false }
    end
  end
end

