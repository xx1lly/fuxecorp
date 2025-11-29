require_relative '../utils/colorize'
require_relative '../core/scanner'
require_relative 'info_gathering'
require_relative 'web_audit'
require_relative 'sql_injection'
require_relative 'xss'
require_relative 'directory_scanning'
require_relative 'vulnerability_scanning'
require_relative 'ssl_analysis'

class Automation
  def self.full_web_scan(url)
    puts Colorize.yellow("Starting full web scan on #{url}")
    results = {}
    
    puts Colorize.cyan("Step 1: Information Gathering")
    results[:info] = {
      headers: WebAudit.analyze_headers(url),
      robots: WebAudit.check_robots_txt(url),
      sitemap: WebAudit.check_sitemap(url),
      cookies: WebAudit.analyze_cookies(url),
      methods: WebAudit.check_http_methods(url),
      waf: WebAudit.check_waf(url)
    }
    
    puts Colorize.cyan("Step 2: Directory Scanning")
    results[:directories] = DirectoryScanning.scan(url)
    
    puts Colorize.cyan("Step 3: Vulnerability Scanning")
    results[:vulnerabilities] = {
      directory_traversal: VulnerabilityScanning.check_directory_traversal(url),
      file_inclusion: VulnerabilityScanning.check_file_inclusion(url),
      command_injection: VulnerabilityScanning.check_command_injection(url)
    }
    
    puts Colorize.cyan("Step 4: SQL Injection Testing")
    results[:sqli] = SQLInjection.full_test(url)
    
    puts Colorize.cyan("Step 5: XSS Testing")
    results[:xss] = XSS.full_test(url)
    
    puts Colorize.green("Full web scan completed")
    results
  end

  def self.full_port_scan(host, ports = nil)
    puts Colorize.yellow("Starting full port scan on #{host}")
    
    if ports.nil?
      ports = (1..65535).to_a
    end
    
    scanner = Scanner.new(host)
    open_ports = scanner.port_scan(ports)
    services = scanner.service_scan(open_ports)
    
    {
      host: host,
      open_ports: open_ports,
      services: services
    }
  end

  def self.reconnaissance(target)
    puts Colorize.yellow("Starting reconnaissance on #{target}")
    results = {}
    
    puts Colorize.cyan("Step 1: WHOIS Lookup")
    results[:whois] = InfoGathering.whois(target)
    
    puts Colorize.cyan("Step 2: DNS Lookup")
    results[:dns] = InfoGathering.dns_lookup(target)
    
    puts Colorize.cyan("Step 3: Subdomain Enumeration")
    results[:subdomains] = InfoGathering.subdomain_enumeration(target)
    
    puts Colorize.cyan("Step 4: IP Geolocation")
    if results[:dns] && results[:dns][:a] && results[:dns][:a].any?
      ip = results[:dns][:a].first
      results[:geolocation] = InfoGathering.ip_geolocation(ip)
    end
    
    puts Colorize.cyan("Step 5: OS Detection")
    if results[:dns] && results[:dns][:a] && results[:dns][:a].any?
      ip = results[:dns][:a].first
      results[:os] = InfoGathering.os_detection(ip)
    end
    
    puts Colorize.green("Reconnaissance completed")
    results
  end

  def self.vulnerability_assessment(target)
    puts Colorize.yellow("Starting vulnerability assessment on #{target}")
    results = {}
    
    puts Colorize.cyan("Step 1: Port Scanning")
    port_results = full_port_scan(target, [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080])
    results[:ports] = port_results
    
    puts Colorize.cyan("Step 2: Service Detection")
    results[:services] = port_results[:services]
    
    puts Colorize.cyan("Step 3: SSL/TLS Analysis")
    if port_results[:open_ports].include?(443)
      results[:ssl] = SSLAnalysis.check_certificate(target, 443)
    end
    
    puts Colorize.cyan("Step 4: Web Application Testing")
    if port_results[:open_ports].include?(80) || port_results[:open_ports].include?(443)
      url = port_results[:open_ports].include?(443) ? "https://#{target}" : "http://#{target}"
      web_results = full_web_scan(url)
      results[:web] = web_results
    end
    
    puts Colorize.green("Vulnerability assessment completed")
    results
  end

  def self.scheduled_scan(target, interval = 3600)
    loop do
      puts Colorize.yellow("Running scheduled scan at #{Time.now}")
      results = vulnerability_assessment(target)
      
      reporter = Reporter.new
      reporter.add_result("Scheduled Scan", results)
      reporter.export_json("scan_#{Time.now.to_i}.json")
      
      sleep(interval)
    end
  end
end

