require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CachePoisoning
  def self.test_host_header_injection(url)
    uri = URI(url)
    host = uri.host
    
    malicious_hosts = [
      "evil.com",
      "evil.com:80",
      "#{host}.evil.com",
      "evil.com\\r\\nX-Forwarded-Host: #{host}",
      "evil.com\\r\\nX-Real-IP: 127.0.0.1"
    ]
    
    results = []
    
    malicious_hosts.each do |malicious|
      begin
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Get.new(uri.path)
        req['Host'] = malicious
        req['X-Forwarded-Host'] = malicious
        req['X-Real-IP'] = '127.0.0.1'
        
        res = http.request(req)
        
        if res.body.include?(malicious.split('\\').first) || res['Location']&.include?(malicious.split('\\').first)
          puts Colorize.red("Host header injection: #{malicious}")
          results << { host: malicious, vulnerable: true, response: res.body[0..200] }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_cache_key_manipulation(url)
    uri = URI(url)
    
    cache_keys = [
      'X-Forwarded-Host',
      'X-Host',
      'X-Forwarded-Server',
      'X-HTTP-Host-Override',
      'Forwarded'
    ]
    
    results = []
    
    cache_keys.each do |key|
      begin
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Get.new(uri.path)
        req[key] = 'evil.com'
        
        res = http.request(req)
        
        if res.body.include?('evil.com') || res['Location']&.include?('evil.com')
          puts Colorize.red("Cache key manipulation: #{key}")
          results << { key: key, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_unkeyed_headers(url)
    unkeyed_headers = [
      'X-Forwarded-Host',
      'X-Forwarded-Scheme',
      'X-Original-URL',
      'X-Rewrite-URL',
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Client-IP',
      'X-Originating-IP',
      'X-Remote-IP',
      'X-Remote-Addr',
      'X-Forwarded',
      'Forwarded-For',
      'Forwarded'
    ]
    
    results = []
    
    unkeyed_headers.each do |header|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Get.new(uri.path)
        req[header] = 'evil.com'
        
        res = http.request(req)
        
        if res.body.include?('evil.com') || res['Location']&.include?('evil.com') || res['Content-Location']&.include?('evil.com')
          puts Colorize.red("Unkeyed header: #{header}")
          results << { header: header, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_parameter_pollution(url)
    params = ['utm_source', 'utm_medium', 'utm_campaign', 'ref', 'source', 'redirect', 'url', 'next', 'return']
    
    results = []
    
    params.each do |param|
      begin
        test_url = url.include?('?') ? "#{url}&#{param}=evil.com" : "#{url}?#{param}=evil.com"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('evil.com') || response['Location']&.include?('evil.com'))
          puts Colorize.red("Parameter pollution: #{param}")
          results << { parameter: param, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_cache_deception(url)
    paths = [
      '/index.html/evil.css',
      '/index.html/evil.js',
      '/index.html/evil.png',
      '/index.html/evil.jpg',
      '/index.html/evil.gif',
      '/index.html/evil.svg',
      '/index.html/evil.woff',
      '/index.html/evil.woff2',
      '/index.html/evil.ttf',
      '/index.html/evil.eot'
    ]
    
    results = []
    
    paths.each do |path|
      begin
        uri = URI(url)
        test_uri = URI.join(url, path)
        
        http = Net::HTTP.new(test_uri.host, test_uri.port)
        http.use_ssl = test_uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Get.new(test_uri.path)
        req['Accept'] = 'text/css,*/*;q=0.1'
        
        res = http.request(req)
        
        if res.code.to_i == 200 && res.body.include?('html') && res['Content-Type']&.include?('text/css')
          puts Colorize.red("Cache deception: #{path}")
          results << { path: path, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end
end

