require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class WebAudit
  def self.analyze_headers(url)
    response = Network.http_request(url)
    return nil unless response
    
    headers = {}
    response.each_header { |k, v| headers[k] = v }
    
    security_headers = {
      'X-Frame-Options' => 'Clickjacking protection',
      'X-Content-Type-Options' => 'MIME sniffing protection',
      'X-XSS-Protection' => 'XSS protection',
      'Strict-Transport-Security' => 'HSTS',
      'Content-Security-Policy' => 'CSP'
    }
    
    { headers: headers, security: security_headers }
  end

  def self.check_robots_txt(url)
    response = Network.http_request("#{url}/robots.txt")
    response&.code == "200" ? response.body : nil
  end

  def self.check_sitemap(url)
    response = Network.http_request("#{url}/sitemap.xml")
    response&.code == "200" ? response.body : nil
  end

  def self.analyze_cookies(url)
    response = Network.http_request(url)
    return nil unless response
    
    cookies = response.get_fields('Set-Cookie')
    return nil unless cookies
    
    cookies.map do |cookie|
      {
        cookie: cookie,
        httponly: cookie.include?('HttpOnly'),
        secure: cookie.include?('Secure')
      }
    end
  end

  def self.check_http_methods(url)
    methods = %w[GET POST PUT DELETE PATCH OPTIONS HEAD TRACE]
    results = {}
    
    methods.each do |method|
      begin
        response = Network.http_request(url, method.downcase.to_sym)
        if response && response.code != "405" && response.code != "501"
          results[method] = { allowed: true, code: response.code }
        else
          results[method] = { allowed: false }
        end
      rescue
        results[method] = { allowed: false }
      end
    end
    
    results
  end

  def self.find_hidden_files(url, wordlist = nil)
    wordlist ||= %w[.htaccess .htpasswd .git .svn .env config.php backup.sql admin.php phpinfo.php test.php wp-config.php .gitignore .DS_Store web.config]
    
    found = []
    wordlist.each do |file|
      begin
        test_url = url.end_with?("/") ? "#{url}#{file}" : "#{url}/#{file}"
        response = Network.http_request(test_url)
        if response&.code == "200"
          puts Colorize.green("Found: #{test_url}")
          found << test_url
        elsif response&.code == "403"
          puts Colorize.yellow("Forbidden: #{test_url}")
        end
      rescue
      end
    end
    found
  end

  def self.analyze_forms(url)
    response = Network.http_request(url)
    return [] unless response
    
    body = response.body
    forms = body.scan(/<form[^>]*>(.*?)<\/form>/mi)
    
    forms.map do |form|
      action = form[0].match(/action=["']([^"']+)["']/i)
      method = form[0].match(/method=["']([^"']+)["']/i)
      { action: action[1] if action, method: method[1] if method }
    end
  end

  def self.check_waf(url)
    response = Network.http_request(url, :get, { 'User-Agent' => '../../../etc/passwd' })
    return nil unless response
    
    headers_str = response.headers.to_s.downcase
    wafs = {
      'cloudflare' => headers_str.include?('cloudflare'),
      'akamai' => headers_str.include?('akamai'),
      'incapsula' => headers_str.include?('incapsula'),
      'sucuri' => headers_str.include?('sucuri'),
      'modsecurity' => headers_str.include?('mod_security'),
      'barracuda' => headers_str.include?('barracuda')
    }
    
    detected = wafs.select { |_, v| v }.keys
    detected.any? ? detected : nil
  end
end

