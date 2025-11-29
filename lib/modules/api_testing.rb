require 'uri'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class APITesting
  def self.test_endpoint(url, method = :get, headers = {}, data = nil)
    response = Network.http_request(url, method, headers, data)
    return nil unless response
    
    {
      status: response.code,
      headers: response.to_hash,
      body: response.body,
      length: response.body.length,
      time: Time.now
    }
  end

  def self.test_authentication(url, auth_type, credentials)
    headers = {}
    
    case auth_type.downcase
    when 'basic'
      require 'base64'
      auth_string = Base64.encode64("#{credentials[:username]}:#{credentials[:password]}").strip
      headers['Authorization'] = "Basic #{auth_string}"
    when 'bearer'
      headers['Authorization'] = "Bearer #{credentials[:token]}"
    when 'apikey'
      headers['X-API-Key'] = credentials[:key]
    when 'custom'
      headers[credentials[:header_name]] = credentials[:header_value]
    end
    
    test_endpoint(url, :get, headers)
  end

  def self.test_rate_limiting(url, requests = 100)
    results = []
    start_time = Time.now
    
    requests.times do |i|
      response = Network.http_request(url)
      next unless response
      
      results << {
        request: i + 1,
        status: response.code,
        time: Time.now
      }
      
      if response.code == "429"
        puts Colorize.red("Rate limit hit at request #{i + 1}")
        break
      end
    end
    
    elapsed = Time.now - start_time
    {
      total_requests: results.length,
      elapsed_time: elapsed,
      requests_per_second: results.length / elapsed,
      results: results
    }
  end

  def self.test_cors(url)
    response = Network.http_request(url, :options, {
      'Origin' => 'https://evil.com',
      'Access-Control-Request-Method' => 'GET',
      'Access-Control-Request-Headers' => 'X-Requested-With'
    })
    
    return nil unless response
    
    cors_headers = {
      'Access-Control-Allow-Origin' => response['Access-Control-Allow-Origin'],
      'Access-Control-Allow-Methods' => response['Access-Control-Allow-Methods'],
      'Access-Control-Allow-Headers' => response['Access-Control-Allow-Headers'],
      'Access-Control-Allow-Credentials' => response['Access-Control-Allow-Credentials']
    }
    
    {
      vulnerable: cors_headers['Access-Control-Allow-Origin'] == '*',
      headers: cors_headers
    }
  end

  def self.test_json_injection(url, payload)
    begin
      data = JSON.generate(payload)
      response = Network.http_request(url, :post, { 'Content-Type' => 'application/json' }, data)
      return nil unless response
      
      {
        status: response.code,
        body: response.body,
        injected: response.body.include?(payload.to_s)
      }
    rescue
      nil
    end
  end

  def self.test_xml_injection(url, payload)
    xml = "<?xml version=\"1.0\"?><root>#{payload}</root>"
    response = Network.http_request(url, :post, { 'Content-Type' => 'application/xml' }, xml)
    return nil unless response
    
    {
      status: response.code,
      body: response.body,
      injected: response.body.include?(payload)
    }
  end

  def self.test_parameter_pollution(url, param, values)
    test_url = url.include?("?") ? "#{url}&#{param}=#{values.join("&#{param}=")}" : "#{url}?#{param}=#{values.join("&#{param}=")}"
    response = Network.http_request(test_url)
    return nil unless response
    
    {
      status: response.code,
      body: response.body,
      url: test_url
    }
  end

  def self.test_idor(url, id1, id2)
    response1 = Network.http_request("#{url}/#{id1}")
    response2 = Network.http_request("#{url}/#{id2}")
    
    return nil unless response1 && response2
    
    {
      id1: { status: response1.code, body: response1.body },
      id2: { status: response2.code, body: response2.body },
      vulnerable: response1.body == response2.body && id1 != id2
    }
  end

  def self.test_mass_assignment(url, params)
    data = JSON.generate(params)
    response = Network.http_request(url, :post, { 'Content-Type' => 'application/json' }, data)
    return nil unless response
    
    {
      status: response.code,
      body: response.body,
      params: params
    }
  end
end

