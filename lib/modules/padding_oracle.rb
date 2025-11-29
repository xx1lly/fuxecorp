require 'uri'
require 'net/http'
require 'openssl'
require_relative '../utils/network'
require_relative '../utils/colorize'

class PaddingOracle
  def self.test_padding_oracle(url, encrypted_data_param = 'data')
    begin
      uri = URI(url)
      
      test_cases = [
        encrypted_data_param + '=' + 'A' * 16,
        encrypted_data_param + '=' + 'A' * 32,
        encrypted_data_param + '=' + 'A' * 48
      ]
      
      results = []
      
      test_cases.each do |test_data|
        begin
          test_url = url.include?('?') ? "#{url}&#{test_data}" : "#{url}?#{test_data}"
          start = Time.now
          response = Network.http_request(test_url)
          elapsed = Time.now - start
          
          if response
            error_messages = ['padding', 'decrypt', 'invalid', 'error', 'bad', 'malformed']
            body_lower = response.body.downcase
            
            if error_messages.any? { |msg| body_lower.include?(msg) }
              if elapsed < 0.1
                puts Colorize.red("Padding oracle detected")
                results << { vulnerable: true, test: test_data }
              end
            end
          end
        rescue => e
        end
      end
      
      results
    rescue => e
      []
    end
  end

  def self.test_cbc_padding(url, ciphertext_param = 'ciphertext')
    begin
      test_url = url.include?('?') ? "#{url}&#{ciphertext_param}=test" : "#{url}?#{ciphertext_param}=test"
      response = Network.http_request(test_url)
      
      if response
        error_messages = ['padding', 'pkcs', 'invalid padding', 'bad padding']
        body_lower = response.body.downcase
        
        if error_messages.any? { |msg| body_lower.include?(msg) }
          puts Colorize.red("CBC padding oracle detected")
          return { vulnerable: true }
        end
      end
    rescue => e
    end
    
    { vulnerable: false }
  end
end

