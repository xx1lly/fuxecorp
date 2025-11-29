require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class Fuzzing
  def self.fuzz_parameters(url, wordlist = nil)
    wordlist ||= %w[id user username email password pass pwd login admin test debug dev staging prod production api key token session cookie auth authorization bearer x-api-key x-auth-token x-access-token x-csrf-token csrf token _token _csrf csrf_token access_token refresh_token api_key secret key secret_key private_key public_key]
    
    results = []
    wordlist.each do |param|
      begin
        test_url = url.include?("?") ? "#{url}&#{param}=test" : "#{url}?#{param}=test"
        response = Network.http_request(test_url)
        next unless response
        
        if response.code == "200" && response.body.length > 0
          puts Colorize.green("Parameter found: #{param}")
          results << { parameter: param, url: test_url, status: response.code }
        end
      rescue
      end
    end
    results
  end

  def self.fuzz_paths(base_url, wordlist = nil)
    wordlist ||= %w[admin api v1 v2 v3 test dev staging prod production backup old archive tmp temp cache log logs config configs configuration settings setup install installer update upgrade patch fix bug bugfix hotfix critical urgent important secret private hidden internal external public demo sandbox beta alpha release latest current new old version v1 v2 v3]
    
    results = []
    wordlist.each do |path|
      begin
        test_url = base_url.end_with?("/") ? "#{base_url}#{path}" : "#{base_url}/#{path}"
        response = Network.http_request(test_url)
        next unless response
        
        case response.code
        when "200"
          puts Colorize.green("Path found: #{test_url} (200)")
          results << { path: path, url: test_url, status: "200" }
        when "403"
          puts Colorize.yellow("Forbidden: #{test_url} (403)")
          results << { path: path, url: test_url, status: "403" }
        when "301", "302"
          location = response['Location']
          puts Colorize.cyan("Redirect: #{test_url} -> #{location}")
          results << { path: path, url: test_url, status: response.code, redirect: location }
        end
      rescue
      end
    end
    results
  end

  def self.fuzz_headers(url, wordlist = nil)
    wordlist ||= %w[X-Forwarded-For X-Real-IP X-Originating-IP X-Remote-IP X-Remote-Addr X-Client-IP X-ProxyUser-Ip X-Original-URL X-Rewrite-URL X-Forwarded-Host X-Forwarded-Server X-Forwarded-Proto X-Forwarded-Port X-Forwarded-Prefix X-Forwarded-Ssl X-Forwarded-Scheme X-Forwarded-Protocol X-Forwarded-Protocols X-Forwarded-Protocol-Version X-Forwarded-Protocol-Versions X-Forwarded-Protocol-Version-Major X-Forwarded-Protocol-Version-Minor X-Forwarded-Protocol-Version-Patch X-Forwarded-Protocol-Version-Build X-Forwarded-Protocol-Version-Revision X-Forwarded-Protocol-Version-Status X-Forwarded-Protocol-Version-Status-Message X-Forwarded-Protocol-Version-Status-Code X-Forwarded-Protocol-Version-Status-Description X-Forwarded-Protocol-Version-Status-Details X-Forwarded-Protocol-Version-Status-Error X-Forwarded-Protocol-Version-Status-Error-Message X-Forwarded-Protocol-Version-Status-Error-Code X-Forwarded-Protocol-Version-Status-Error-Description X-Forwarded-Protocol-Version-Status-Error-Details]
    
    results = []
    wordlist.each do |header|
      begin
        response = Network.http_request(url, :get, { header => "test" })
        next unless response
        
        if response.code == "200" && response.body.length > 0
          puts Colorize.green("Header accepted: #{header}")
          results << { header: header, status: response.code }
        end
      rescue
      end
    end
    results
  end

  def self.fuzz_methods(url)
    methods = %w[GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK SEARCH]
    results = {}
    
    methods.each do |method|
      begin
        response = Network.http_request(url, method.downcase.to_sym)
        next unless response
        
        if response.code != "405" && response.code != "501"
          puts Colorize.green("#{method}: Allowed (#{response.code})")
          results[method] = { allowed: true, code: response.code }
        else
          puts Colorize.red("#{method}: Not Allowed")
          results[method] = { allowed: false }
        end
      rescue
        results[method] = { allowed: false }
      end
    end
    
    results
  end

  def self.fuzz_values(url, param, wordlist = nil)
    wordlist ||= %w[null nil none empty "" '' 0 -1 1 true false True False TRUE FALSE yes no Yes No YES NO admin administrator root test Test TEST debug Debug DEBUG dev Dev DEV staging Staging STAGING prod Prod PROD production Production PRODUCTION]
    
    results = []
    wordlist.each do |value|
      begin
        test_url = url.include?("?") ? "#{url}&#{param}=#{value}" : "#{url}?#{param}=#{value}"
        response = Network.http_request(test_url)
        next unless response
        
        if response.code == "200" && response.body.length > 0
          puts Colorize.green("Value accepted: #{value}")
          results << { parameter: param, value: value, url: test_url, status: response.code }
        end
      rescue
      end
    end
    results
  end
end

