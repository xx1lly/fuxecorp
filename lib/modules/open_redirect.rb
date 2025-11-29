require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class OpenRedirect
  REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'returnTo', 'return_to', 'goto', 'go', 'target', 'destination', 'dest', 'r', 'u', 'link', 'linkTo', 'out', 'view', 'image_url', 'continue', 'return_path', 'returnPath', 'success', 'success_url', 'successUrl', 'callback', 'callback_url', 'callbackUrl', 'ret', 'ret_to', 'retTo', 'returl', 'retURL', 'returnurl', 'returnURL', 'redir', 'redir_url', 'redirUrl', 'redirect_uri', 'redirectUri', 'redirect_url', 'redirectUrl', 'redirect_to', 'redirectTo', 'redirect_path', 'redirectPath', 'rurl', 'rURL', 'return_to_url', 'returnToUrl', 'return_url', 'returnUrl', 'return_path', 'returnPath', 'return_to_path', 'returnToPath', 'return_to_url', 'returnToUrl', 'return_to_uri', 'returnToUri', 'return_uri', 'returnUri', 'return_to_path', 'returnToPath', 'return_to_url', 'returnToUrl', 'return_to_uri', 'returnToUri', 'return_uri', 'returnUri', 'return_to_path', 'returnToPath', 'return_to_url', 'returnToUrl', 'return_to_uri', 'returnToUri', 'return_uri', 'returnUri']

  PAYLOADS = [
    'http://evil.com',
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    '////evil.com',
    'http://evil.com/',
    'https://evil.com/',
    '//evil.com/',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '\\evil.com',
    '\\\\evil.com',
    '/\\evil.com',
    '/\\/evil.com',
    'http://evil.com@target.com',
    'https://evil.com@target.com',
    'http://target.com.evil.com',
    'https://target.com.evil.com',
    'http://target.com@evil.com',
    'https://target.com@evil.com',
    '%2f%2fevil.com',
    '%2f%2f%2fevil.com',
    '%2f%2f%2f%2fevil.com',
    'http%3A%2F%2Fevil.com',
    'https%3A%2F%2Fevil.com',
    '%2F%2Fevil.com',
    '%2F%2F%2Fevil.com',
    '%2F%2F%2F%2Fevil.com',
    'http://target.com\\evil.com',
    'https://target.com\\evil.com',
    'http://target.com/evil.com',
    'https://target.com/evil.com',
    'http://target.com//evil.com',
    'https://target.com//evil.com',
    'http://target.com///evil.com',
    'https://target.com///evil.com',
    'http://target.com////evil.com',
    'https://target.com////evil.com',
    'http://target.com/\\evil.com',
    'https://target.com/\\evil.com',
    'http://target.com/\\\\evil.com',
    'https://target.com/\\\\evil.com',
    'http://target.com/\\/evil.com',
    'https://target.com/\\/evil.com',
    'http://target.com/\\//evil.com',
    'https://target.com/\\//evil.com',
    'http://target.com/\\///evil.com',
    'https://target.com/\\///evil.com',
    'http://target.com/\\////evil.com',
    'https://target.com/\\////evil.com',
    'http://target.com/\\/\\/evil.com',
    'https://target.com/\\/\\/evil.com',
    'http://target.com/\\/\\//evil.com',
    'https://target.com/\\/\\//evil.com',
    'http://target.com/\\/\\///evil.com',
    'https://target.com/\\/\\///evil.com',
    'http://target.com/\\/\\////evil.com',
    'https://target.com/\\/\\////evil.com',
    'http://target.com/\\/\\/\\/evil.com',
    'https://target.com/\\/\\/\\/evil.com',
    'http://target.com/\\/\\/\\//evil.com',
    'https://target.com/\\/\\/\\//evil.com',
    'http://target.com/\\/\\/\\///evil.com',
    'https://target.com/\\/\\/\\///evil.com',
    'http://target.com/\\/\\/\\////evil.com',
    'https://target.com/\\/\\/\\////evil.com',
    'http://target.com/\\/\\/\\/\\/evil.com',
    'https://target.com/\\/\\/\\/\\/evil.com',
    'http://target.com/\\/\\/\\/\\//evil.com',
    'https://target.com/\\/\\/\\/\\//evil.com',
    'http://target.com/\\/\\/\\/\\///evil.com',
    'https://target.com/\\/\\/\\/\\///evil.com',
    'http://target.com/\\/\\/\\/\\////evil.com',
    'https://target.com/\\/\\/\\/\\////evil.com'
  ]

  def self.test_open_redirect(url, parameter = nil)
    if parameter.nil?
      REDIRECT_PARAMS.each do |param|
        result = test_parameter(url, param)
        return result if result[:vulnerable]
      end
    else
      return test_parameter(url, parameter)
    end
    
    { vulnerable: false }
  end

  def self.test_parameter(url, parameter)
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response
          location = response['Location'] || response['location']
          
          if location && (location.include?('evil.com') || location.include?('javascript:') || location.include?('data:'))
            puts Colorize.red("Open redirect vulnerability found!")
            puts Colorize.yellow("Parameter: #{parameter}, Payload: #{payload}")
            puts Colorize.yellow("Redirects to: #{location}")
            return { vulnerable: true, parameter: parameter, payload: payload, location: location }
          end
        end
      rescue => e
      end
    end
    
    { vulnerable: false }
  end

  def self.test_header_based_redirect(url)
    headers = {
      'X-Forwarded-Host' => 'evil.com',
      'X-Forwarded-Server' => 'evil.com',
      'X-Original-URL' => 'http://evil.com',
      'X-Rewrite-URL' => 'http://evil.com',
      'X-Forwarded-For' => 'evil.com',
      'X-Real-IP' => 'evil.com',
      'X-Client-IP' => 'evil.com',
      'X-Originating-IP' => 'evil.com',
      'X-Remote-IP' => 'evil.com',
      'X-Remote-Addr' => 'evil.com',
      'X-Forwarded' => 'for=evil.com',
      'Forwarded-For' => 'evil.com',
      'Forwarded' => 'for=evil.com'
    }
    
    results = []
    
    headers.each do |header, value|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Get.new(uri.path)
        req[header] = value
        
        res = http.request(req)
        
        location = res['Location'] || res['location']
        
        if location && location.include?('evil.com')
          puts Colorize.red("Header-based redirect: #{header}")
          results << { header: header, vulnerable: true, location: location }
        end
      rescue => e
      end
    end
    
    results
  end
end

