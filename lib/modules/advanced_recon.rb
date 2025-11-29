require 'net/http'
require 'uri'
require 'json'
require 'resolv'
require 'digest'
require_relative '../utils/network'
require_relative '../utils/colorize'

class AdvancedRecon
  def self.shodan_search(query, api_key = nil)
    return nil unless api_key
    
    begin
      uri = URI("https://api.shodan.io/shodan/host/search?key=#{api_key}&query=#{URI.encode_www_form_component(query)}")
      response = Net::HTTP.get_response(uri)
      JSON.parse(response.body) if response.code == "200"
    rescue
      nil
    end
  end

  def self.censys_search(query, api_id = nil, api_secret = nil)
    return nil unless api_id && api_secret
    
    begin
      uri = URI("https://search.censys.io/api/v1/search/ipv4")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      req = Net::HTTP::Post.new(uri.path)
      req.basic_auth(api_id, api_secret)
      req['Content-Type'] = 'application/json'
      req.body = { q: query, page: 1, fields: ['ip', 'protocols', 'location.country'] }.to_json
      res = http.request(req)
      JSON.parse(res.body) if res.code == "200"
    rescue
      nil
    end
  end

  def self.virustotal_domain(domain, api_key = nil)
    return nil unless api_key
    
    begin
      uri = URI("https://www.virustotal.com/vtapi/v2/domain/report?apikey=#{api_key}&domain=#{domain}")
      response = Net::HTTP.get_response(uri)
      JSON.parse(response.body) if response.code == "200"
    rescue
      nil
    end
  end

  def self.virustotal_ip(ip, api_key = nil)
    return nil unless api_key
    
    begin
      uri = URI("https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=#{api_key}&ip=#{ip}")
      response = Net::HTTP.get_response(uri)
      JSON.parse(response.body) if response.code == "200"
    rescue
      nil
    end
  end

  def self.haveibeenpwned(email, api_key = nil)
    return nil unless api_key
    
    begin
      hash = Digest::SHA1.hexdigest(email).upcase
      prefix = hash[0..4]
      suffix = hash[5..-1]
      
      uri = URI("https://api.pwnedpasswords.com/range/#{prefix}")
      response = Net::HTTP.get_response(uri)
      
      if response.code == "200"
        response.body.split("\n").each do |line|
          if line.start_with?(suffix)
            count = line.split(':').last.to_i
            return { pwned: true, count: count }
          end
        end
      end
      
      { pwned: false }
    rescue
      nil
    end
  end

  def self.wayback_machine(domain)
    begin
      uri = URI("http://web.archive.org/cdx/search/cdx?url=#{domain}/*&output=json&collapse=urlkey")
      response = Net::HTTP.get_response(uri)
      
      if response.code == "200"
        data = JSON.parse(response.body)
        data[1..-1].map { |entry| entry[2] }.uniq
      else
        []
      end
    rescue
      []
    end
  end

  def self.certificate_transparency(domain)
    begin
      uri = URI("https://crt.sh/?q=#{domain}&output=json")
      response = Net::HTTP.get_response(uri)
      
      if response.code == "200"
        data = JSON.parse(response.body)
        data.map { |entry| entry['name_value'] }.flatten.uniq
      else
        []
      end
    rescue
      []
    end
  end

  def self.dns_dumpster(domain)
    begin
      uri = URI("https://dnsdumpster.com/")
      response = Net::HTTP.get_response(uri)
      
      csrf_token = response.body.match(/name="csrfmiddlewaretoken" value="([^"]+)"/)
      return [] unless csrf_token
      
      cookie = response.get_fields('Set-Cookie')&.first
      return [] unless cookie
      
      session_cookie = cookie.match(/([^;]+)/)[1]
      
      uri = URI("https://dnsdumpster.com/")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      req = Net::HTTP::Post.new(uri.path)
      req['Cookie'] = session_cookie
      req['Referer'] = 'https://dnsdumpster.com/'
      req.set_form_data('csrfmiddlewaretoken' => csrf_token[1], 'targetip' => domain)
      res = http.request(req)
      
      if res.code == "200"
        subdomains = res.body.scan(/([a-zA-Z0-9][a-zA-Z0-9-]*\.#{domain.gsub('.', '\.')})/).flatten.uniq
        subdomains
      else
        []
      end
    rescue
      []
    end
  end

  def self.security_headers_scan(url)
    response = Network.http_request(url)
    return nil unless response
    
    headers = {}
    response.each_header { |k, v| headers[k] = v }
    
    security_headers = {
      'X-Frame-Options' => headers['X-Frame-Options'],
      'X-Content-Type-Options' => headers['X-Content-Type-Options'],
      'X-XSS-Protection' => headers['X-XSS-Protection'],
      'Strict-Transport-Security' => headers['Strict-Transport-Security'],
      'Content-Security-Policy' => headers['Content-Security-Policy'],
      'X-Permitted-Cross-Domain-Policies' => headers['X-Permitted-Cross-Domain-Policies'],
      'Referrer-Policy' => headers['Referrer-Policy'],
      'Permissions-Policy' => headers['Permissions-Policy'],
      'X-Download-Options' => headers['X-Download-Options'],
      'X-DNS-Prefetch-Control' => headers['X-DNS-Prefetch-Control']
    }
    
    {
      headers: headers,
      security_headers: security_headers,
      score: calculate_security_score(security_headers)
    }
  end

  def self.calculate_security_score(headers)
    score = 0
    max_score = 10
    
    score += 1 if headers['X-Frame-Options']
    score += 1 if headers['X-Content-Type-Options']
    score += 1 if headers['X-XSS-Protection']
    score += 1 if headers['Strict-Transport-Security']
    score += 1 if headers['Content-Security-Policy']
    score += 1 if headers['X-Permitted-Cross-Domain-Policies']
    score += 1 if headers['Referrer-Policy']
    score += 1 if headers['Permissions-Policy']
    score += 1 if headers['X-Download-Options']
    score += 1 if headers['X-DNS-Prefetch-Control']
    
    (score.to_f / max_score * 100).round
  end
end

