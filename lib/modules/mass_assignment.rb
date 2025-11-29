require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class MassAssignment
  def self.test_mass_assignment(url, method = :post)
    dangerous_params = [
      'admin', 'is_admin', 'role', 'user_role', 'privileges', 'permissions',
      'active', 'enabled', 'verified', 'confirmed', 'approved',
      'balance', 'credit', 'points', 'score', 'rating',
      'price', 'discount', 'cost', 'amount',
      'owner_id', 'user_id', 'creator_id',
      'created_at', 'updated_at', 'deleted_at',
      'password', 'password_hash', 'password_salt',
      'api_key', 'secret', 'token', 'access_token'
    ]
    
    results = []
    
    dangerous_params.each do |param|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = case method
        when :post then Net::HTTP::Post.new(uri.path)
        when :put then Net::HTTP::Put.new(uri.path)
        when :patch then Net::HTTP::Patch.new(uri.path)
        else Net::HTTP::Post.new(uri.path)
        end
        
        req.set_form_data(param => 'test_value')
        
        res = http.request(req)
        
        if res.code.to_i == 200 || res.code.to_i == 201
          if res.body.include?('test_value') || res.body.include?(param)
            puts Colorize.red("Mass assignment possible: #{param}")
            results << { parameter: param, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_json_mass_assignment(url)
    dangerous_fields = {
      'admin' => true,
      'is_admin' => true,
      'role' => 'admin',
      'privileges' => ['admin', 'user'],
      'balance' => 999999,
      'verified' => true,
      'approved' => true
    }
    
    results = []
    
    dangerous_fields.each do |field, value|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/json'
        req.body = { field => value }.to_json
        
        res = http.request(req)
        
        if res.code.to_i == 200 || res.code.to_i == 201
          if res.body.include?(value.to_s) || res.body.include?(field)
            puts Colorize.red("JSON mass assignment: #{field}")
            results << { field: field, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end
end

