require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class IDOR
  def self.test_sequential_ids(url, id_param = 'id', start_id = 1, end_id = 100)
    results = []
    
    (start_id..end_id).each do |id|
      begin
        test_url = url.include?('?') ? "#{url}&#{id_param}=#{id}" : "#{url}?#{id_param}=#{id}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          if response.body.length > 100 && !response.body.include?('404') && !response.body.include?('Not Found') && !response.body.include?('Access Denied')
            puts Colorize.red("Accessible ID: #{id}")
            results << { id: id, accessible: true, response_length: response.body.length }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_user_id_manipulation(url, user_id_param = 'user_id', target_id = nil)
    if target_id.nil?
      target_id = rand(1000..9999)
    end
    
    begin
      test_url = url.include?('?') ? "#{url}&#{user_id_param}=#{target_id}" : "#{url}?#{user_id_param}=#{target_id}"
      response = Network.http_request(test_url)
      
      if response && response.code.to_i == 200
        if response.body.include?('email') || response.body.include?('username') || response.body.include?('profile') || response.body.include?('user')
          puts Colorize.red("IDOR vulnerability: Can access user #{target_id}")
          return { vulnerable: true, user_id: target_id, data_found: true }
        end
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.test_object_reference(url, object_param = 'object_id')
    test_ids = [1, 2, 3, 10, 100, 1000, 9999, -1, 0, 'admin', 'test', '../', '../../']
    
    results = []
    
    test_ids.each do |test_id|
      begin
        test_url = url.include?('?') ? "#{url}&#{object_param}=#{test_id}" : "#{url}?#{object_param}=#{test_id}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          if response.body.length > 50 && !response.body.include?('404')
            puts Colorize.red("Object accessible: #{test_id}")
            results << { object_id: test_id, accessible: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_http_method_override(url, id_param = 'id')
    methods = [:get, :post, :put, :delete, :patch]
    test_id = 1
    
    results = []
    
    methods.each do |method|
      begin
        test_url = url.include?('?') ? "#{url}&#{id_param}=#{test_id}" : "#{url}?#{id_param}=#{test_id}"
        response = Network.http_request(test_url, method)
        
        if response && (response.code.to_i == 200 || response.code.to_i == 204)
          puts Colorize.yellow("Method #{method.to_s.upcase} allowed on ID #{test_id}")
          results << { method: method, id: test_id, allowed: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_parameter_pollution(url, id_param = 'id')
    pollution_payloads = [
      "#{id_param}=1&#{id_param}=2",
      "#{id_param}=1&#{id_param}=999",
      "#{id_param}=admin&#{id_param}=1",
      "#{id_param}[]=1&#{id_param}[]=2"
    ]
    
    results = []
    
    pollution_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{payload}" : "#{url}?#{payload}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i == 200
          if response.body.length > 100
            puts Colorize.yellow("Parameter pollution test: #{payload}")
            results << { payload: payload, response_length: response.body.length }
          end
        end
      rescue => e
      end
    end
    
    results
  end
end

