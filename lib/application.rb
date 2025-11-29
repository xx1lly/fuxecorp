require_relative 'utils/colorize'
require_relative 'utils/network'
require_relative 'utils/crypto'
require_relative 'core/scanner'
require_relative 'core/bruteforcer'
require_relative 'core/reporter'
require_relative 'modules/info_gathering'
require_relative 'modules/web_audit'
require_relative 'modules/sql_injection'
require_relative 'modules/xss'
require_relative 'modules/ssl_analysis'
require_relative 'modules/directory_scanning'
require_relative 'modules/exploits'
require_relative 'modules/vulnerability_scanning'
require_relative 'modules/cryptography'
require_relative 'modules/fuzzing'
require_relative 'modules/wordlist_generator'
require_relative 'modules/api_testing'
require_relative 'modules/network_analysis'
require_relative 'modules/automation'
require_relative 'modules/port_scanning'
require_relative 'modules/session_management'
require_relative 'modules/file_upload'
require_relative 'modules/xxe'
require_relative 'modules/ssrf'
require_relative 'modules/waf_bypass'
require_relative 'modules/advanced_recon'
require_relative 'modules/payload_generator'
require_relative 'modules/deserialization'
require_relative 'modules/race_condition'
require_relative 'modules/business_logic'
require_relative 'modules/template_injection'
require_relative 'modules/ldap_injection'
require_relative 'modules/nosql_injection'
require_relative 'utils/logger'

class Application
  def initialize
    @target = nil
    @timeout = 3
    @threads = 50
    @reporter = Reporter.new
    @logger = Logger.new
  end

  def banner
    puts Colorize.red("pentest")
    puts
  end

  def main_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Information Gathering")
      puts Colorize.yellow("  [2]  Port Scanning")
      puts Colorize.yellow("  [3]  Vulnerability Scanning")
      puts Colorize.yellow("  [4]  Web Audit")
      puts Colorize.yellow("  [5]  Bruteforce Attacks")
      puts Colorize.yellow("  [6]  SQL Injection Tests")
      puts Colorize.yellow("  [7]  XSS Tests")
      puts Colorize.yellow("  [8]  Directory Scanning")
      puts Colorize.yellow("  [9]  SSL/TLS Analysis")
      puts Colorize.yellow("  [10] Network Scanning")
      puts Colorize.yellow("  [11] Cryptography")
      puts Colorize.yellow("  [12] Exploits")
      puts Colorize.yellow("  [13] Fuzzing")
      puts Colorize.yellow("  [14] API Testing")
      puts Colorize.yellow("  [15] Wordlist Generator")
      puts Colorize.yellow("  [16] Automation")
      puts Colorize.yellow("  [17] Session Management")
      puts Colorize.yellow("  [18] File Upload Testing")
      puts Colorize.yellow("  [19] XXE Testing")
      puts Colorize.yellow("  [20] SSRF Testing")
      puts Colorize.yellow("  [21] WAF Bypass")
      puts Colorize.yellow("  [22] Advanced Recon")
      puts Colorize.yellow("  [23] Payload Generator")
      puts Colorize.yellow("  [24] Deserialization")
      puts Colorize.yellow("  [25] Race Condition")
      puts Colorize.yellow("  [26] Business Logic")
      puts Colorize.yellow("  [27] Template Injection")
      puts Colorize.yellow("  [28] LDAP Injection")
      puts Colorize.yellow("  [29] NoSQL Injection")
      puts Colorize.yellow("  [30] Reporting")
      puts Colorize.yellow("  [31] Settings")
      puts Colorize.yellow("  [0]  Exit")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      handle_menu_choice(choice)
    end
  end

  def handle_menu_choice(choice)
    case choice
    when 1 then info_gathering_menu
    when 2 then port_scanning_menu
    when 3 then vulnerability_scanning_menu
    when 4 then web_audit_menu
    when 5 then bruteforce_menu
    when 6 then sql_injection_menu
    when 7 then xss_testing_menu
    when 8 then directory_scanning_menu
    when 9 then ssl_analysis_menu
    when 10 then network_scanning_menu
    when 11 then cryptography_menu
    when 12 then exploits_menu
    when 13 then fuzzing_menu
    when 14 then api_testing_menu
    when 15 then wordlist_generator_menu
    when 16 then automation_menu
    when 17 then session_management_menu
    when 18 then file_upload_menu
    when 19 then xxe_menu
    when 20 then ssrf_menu
    when 21 then waf_bypass_menu
    when 22 then advanced_recon_menu
    when 23 then payload_generator_menu
    when 24 then deserialization_menu
    when 25 then race_condition_menu
    when 26 then business_logic_menu
    when 27 then template_injection_menu
    when 28 then ldap_injection_menu
    when 29 then nosql_injection_menu
    when 30 then reporting_menu
    when 31 then settings_menu
    when 0 then exit_tool
    else
      puts Colorize.red("Invalid choice")
      sleep(2)
    end
  end

  def info_gathering_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  WHOIS Lookup")
      puts Colorize.yellow("  [2]  DNS Lookup")
      puts Colorize.yellow("  [3]  Reverse DNS")
      puts Colorize.yellow("  [4]  Subdomain Enumeration")
      puts Colorize.yellow("  [5]  IP Geolocation")
      puts Colorize.yellow("  [6]  Banner Grabbing")
      puts Colorize.yellow("  [7]  OS Detection")
      puts Colorize.yellow("  [8]  Full Information Gathering")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter domain/IP: ")
        target = gets.chomp
        result = InfoGathering.whois(target)
        puts result
        @reporter.add_result("WHOIS", result)
        pause
      when 2
        print Colorize.cyan("Enter domain: ")
        target = gets.chomp
        results = InfoGathering.dns_lookup(target)
        results.each { |type, data| puts "#{type}: #{data.join(', ')}" }
        @reporter.add_result("DNS Lookup", results)
        pause
      when 3
        print Colorize.cyan("Enter IP address: ")
        ip = gets.chomp
        result = InfoGathering.reverse_dns(ip)
        puts result ? Colorize.green(result) : Colorize.red("Not found")
        @reporter.add_result("Reverse DNS", result)
        pause
      when 4
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        found = InfoGathering.subdomain_enumeration(domain)
        @reporter.add_result("Subdomain Enumeration", found)
        pause
      when 5
        print Colorize.cyan("Enter IP address: ")
        ip = gets.chomp
        geo = InfoGathering.ip_geolocation(ip)
        if geo
          puts "Country: #{geo['country']}"
          puts "City: #{geo['city']}"
          puts "ISP: #{geo['isp']}"
          puts "Coordinates: #{geo['lat']}, #{geo['lon']}"
        end
        @reporter.add_result("IP Geolocation", geo)
        pause
      when 6
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port: ")
        port = gets.chomp.to_i
        banner = InfoGathering.banner_grab(host, port)
        puts banner || "No banner"
        @reporter.add_result("Banner Grab", banner)
        pause
      when 7
        print Colorize.cyan("Enter IP address: ")
        ip = gets.chomp
        os = InfoGathering.os_detection(ip)
        puts os ? Colorize.green("OS: #{os}") : Colorize.red("Unable to detect")
        @reporter.add_result("OS Detection", os)
        pause
      when 8
        print Colorize.cyan("Enter target: ")
        target = gets.chomp
        puts Colorize.yellow("Running full information gathering...")
        whois_result = InfoGathering.whois(target)
        dns_result = InfoGathering.dns_lookup(target)
        subdomain_result = InfoGathering.subdomain_enumeration(target)
        @reporter.add_result("Full Info Gathering", { whois: whois_result, dns: dns_result, subdomains: subdomain_result })
        pause
      when 0 then return
      end
    end
  end

  def port_scanning_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Quick Scan (Top Ports)")
      puts Colorize.yellow("  [2]  Full Scan (All Ports)")
      puts Colorize.yellow("  [3]  Custom Range Scan")
      puts Colorize.yellow("  [4]  Service Detection")
      puts Colorize.yellow("  [5]  Advanced Scans")
      puts Colorize.yellow("  [6]  Version Detection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 9200]
        scanner = Scanner.new(host, timeout: @timeout, threads: @threads)
        open_ports = scanner.port_scan(top_ports)
        puts Colorize.green("Found #{open_ports.length} open ports")
        @reporter.add_result("Port Scan", { host: host, ports: open_ports })
        pause
      when 2
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        scanner = Scanner.new(host, timeout: @timeout, threads: @threads)
        open_ports = scanner.port_scan(1..65535)
        puts Colorize.green("Found #{open_ports.length} open ports")
        @reporter.add_result("Full Port Scan", { host: host, ports: open_ports })
        pause
      when 3
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port range (e.g., 1-1000): ")
        range = gets.chomp
        if range.include?('-')
          start_port, end_port = range.split('-').map(&:to_i)
          scanner = Scanner.new(host, timeout: @timeout, threads: @threads)
          open_ports = scanner.port_scan(start_port..end_port)
          puts Colorize.green("Found #{open_ports.length} open ports")
          @reporter.add_result("Custom Port Scan", { host: host, ports: open_ports })
        end
        pause
      when 4
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter ports (comma-separated): ")
        ports = gets.chomp.split(',').map(&:to_i)
        scanner = Scanner.new(host)
        services = scanner.service_scan(ports)
        services.each { |s| puts "#{s[:port]}: #{s[:service]}" }
        @reporter.add_result("Service Detection", services)
        pause
      when 5
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter ports (comma-separated): ")
        ports = gets.chomp.split(',').map(&:to_i)
        puts Colorize.cyan("  [1]  Stealth  [2]  FIN  [3]  XMAS  [4]  NULL  [5]  UDP: ")
        scan_type = gets.chomp.to_i
        case scan_type
        when 1
          results = PortScanning.stealth_scan(host, ports)
        when 2
          results = PortScanning.fin_scan(host, ports)
        when 3
          results = PortScanning.xmas_scan(host, ports)
        when 4
          results = PortScanning.null_scan(host, ports)
        when 5
          results = PortScanning.udp_scan(host, ports)
        end
        @reporter.add_result("Advanced Port Scan", results)
        pause
      when 6
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port: ")
        port = gets.chomp.to_i
        result = PortScanning.version_detection(host, port)
        puts "Service: #{result[:service]}" if result
        @reporter.add_result("Version Detection", result)
        pause
      when 0 then return
      end
    end
  end

  def vulnerability_scanning_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Known Vulnerabilities Scan")
      puts Colorize.yellow("  [2]  Directory Traversal Test")
      puts Colorize.yellow("  [3]  File Inclusion Test")
      puts Colorize.yellow("  [4]  Command Injection Test")
      puts Colorize.yellow("  [5]  Open Redirect Test")
      puts Colorize.yellow("  [6]  SSRF Test")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        vulns = []
        vulns << "Heartbleed" if VulnerabilityScanning.check_heartbleed(host)
        vulns << "Shellshock" if VulnerabilityScanning.check_shellshock(host)
        puts vulns.any? ? Colorize.red("Vulnerabilities: #{vulns.join(', ')}") : Colorize.green("No known vulnerabilities")
        @reporter.add_result("Vulnerability Scan", vulns)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = VulnerabilityScanning.check_directory_traversal(url)
        @reporter.add_result("Directory Traversal", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = VulnerabilityScanning.check_file_inclusion(url)
        @reporter.add_result("File Inclusion", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = VulnerabilityScanning.check_command_injection(url)
        @reporter.add_result("Command Injection", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = VulnerabilityScanning.check_open_redirect(url)
        @reporter.add_result("Open Redirect", result)
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = VulnerabilityScanning.check_server_side_request_forgery(url)
        @reporter.add_result("SSRF", result)
        pause
      when 0 then return
      end
    end
  end

  def web_audit_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Analyze Headers")
      puts Colorize.yellow("  [2]  Check robots.txt")
      puts Colorize.yellow("  [3]  Check sitemap.xml")
      puts Colorize.yellow("  [4]  Analyze Cookies")
      puts Colorize.yellow("  [5]  Check HTTP Methods")
      puts Colorize.yellow("  [6]  Find Hidden Files")
      puts Colorize.yellow("  [7]  Analyze Forms")
      puts Colorize.yellow("  [8]  Check WAF")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WebAudit.analyze_headers(url)
        if result
          result[:headers].each { |k, v| puts "#{k}: #{v}" }
          puts "\nSecurity Headers:"
          result[:security].each { |k, v| puts "#{k}: #{v}" }
        end
        @reporter.add_result("Header Analysis", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WebAudit.check_robots_txt(url)
        puts result || "Not found"
        @reporter.add_result("robots.txt", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WebAudit.check_sitemap(url)
        puts result ? result[0..500] : "Not found"
        @reporter.add_result("sitemap.xml", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WebAudit.analyze_cookies(url)
        if result
          result.each { |c| puts "#{c[:cookie]} - HttpOnly: #{c[:httponly]}, Secure: #{c[:secure]}" }
        end
        @reporter.add_result("Cookie Analysis", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WebAudit.check_http_methods(url)
        result.each { |method, data| puts "#{method}: #{data[:allowed] ? 'Allowed' : 'Not Allowed'}" }
        @reporter.add_result("HTTP Methods", result)
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        found = WebAudit.find_hidden_files(url)
        @reporter.add_result("Hidden Files", found)
        pause
      when 7
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        forms = WebAudit.analyze_forms(url)
        puts "Found #{forms.length} forms"
        forms.each { |f| puts "Action: #{f[:action]}, Method: #{f[:method]}" }
        @reporter.add_result("Form Analysis", forms)
        pause
      when 8
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        waf = WebAudit.check_waf(url)
        puts waf ? Colorize.red("WAF detected: #{waf.join(', ')}") : Colorize.green("No WAF detected")
        @reporter.add_result("WAF Check", waf)
        pause
      when 0 then return
      end
    end
  end

  def bruteforce_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  FTP Bruteforce")
      puts Colorize.yellow("  [2]  HTTP Basic Auth Bruteforce")
      puts Colorize.yellow("  [3]  WordPress Bruteforce")
      puts Colorize.yellow("  [4]  SSH Bruteforce")
      puts Colorize.yellow("  [5]  MySQL Bruteforce")
      puts Colorize.yellow("  [6]  PostgreSQL Bruteforce")
      puts Colorize.yellow("  [7]  SMTP Bruteforce")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 21): ")
        port = gets.chomp.to_i
        port = 21 if port == 0
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(host, port: port)
        result = bruteforcer.ftp_bruteforce(username, wordlist)
        @reporter.add_result("FTP Bruteforce", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(url)
        result = bruteforcer.http_basic_bruteforce(url, username, wordlist)
        @reporter.add_result("HTTP Basic Bruteforce", result)
        pause
      when 3
        print Colorize.cyan("Enter WordPress URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(url)
        result = bruteforcer.wordpress_bruteforce(url, username, wordlist)
        @reporter.add_result("WordPress Bruteforce", result)
        pause
      when 4
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 22): ")
        port = gets.chomp.to_i
        port = 22 if port == 0
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(host, port: port)
        result = bruteforcer.ssh_bruteforce(host, port, username, wordlist)
        @reporter.add_result("SSH Bruteforce", result)
        pause
      when 5
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 3306): ")
        port = gets.chomp.to_i
        port = 3306 if port == 0
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(host, port: port)
        result = bruteforcer.mysql_bruteforce(host, port, username, wordlist)
        @reporter.add_result("MySQL Bruteforce", result)
        pause
      when 6
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 5432): ")
        port = gets.chomp.to_i
        port = 5432 if port == 0
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(host, port: port)
        result = bruteforcer.postgresql_bruteforce(host, port, username, wordlist)
        @reporter.add_result("PostgreSQL Bruteforce", result)
        pause
      when 7
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 25): ")
        port = gets.chomp.to_i
        port = 25 if port == 0
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        bruteforcer = Bruteforcer.new(host, port: port)
        result = bruteforcer.smtp_bruteforce(host, port, username, wordlist)
        @reporter.add_result("SMTP Bruteforce", result)
        pause
      when 0 then return
      end
    end
  end

  def sql_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Basic SQL Injection Test")
      puts Colorize.yellow("  [2]  Union-based SQLi")
      puts Colorize.yellow("  [3]  Boolean-based SQLi")
      puts Colorize.yellow("  [4]  Time-based SQLi")
      puts Colorize.yellow("  [5]  Error-based SQLi")
      puts Colorize.yellow("  [6]  Full SQL Injection Test")
      puts Colorize.yellow("  [7]  Enumerate Tables")
      puts Colorize.yellow("  [8]  Enumerate Columns")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.test(url, :basic)
        @reporter.add_result("SQL Injection Basic", result)
        pause
      when 2
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.test(url, :union)
        @reporter.add_result("SQL Injection Union", result)
        pause
      when 3
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.test(url, :boolean)
        @reporter.add_result("SQL Injection Boolean", result)
        pause
      when 4
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.time_based_test(url)
        @reporter.add_result("SQL Injection Time-based", result)
        pause
      when 5
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.test(url, :error)
        @reporter.add_result("SQL Injection Error-based", result)
        pause
      when 6
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = SQLInjection.full_test(url)
        @reporter.add_result("SQL Injection Full", result)
        pause
      when 0 then return
      end
    end
  end

  def xss_testing_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Reflected XSS Test")
      puts Colorize.yellow("  [2]  DOM-based XSS Test")
      puts Colorize.yellow("  [3]  Full XSS Test")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL with parameter: ")
        url = gets.chomp
        result = XSS.test(url, :reflected)
        @reporter.add_result("XSS Reflected", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        XSS.dom_test(url)
        @reporter.add_result("XSS DOM", true)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = XSS.full_test(url)
        @reporter.add_result("XSS Full", result)
        pause
      when 0 then return
      end
    end
  end

  def directory_scanning_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Quick Directory Scan")
      puts Colorize.yellow("  [2]  Full Directory Scan")
      puts Colorize.yellow("  [3]  Scan with Extensions")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        found = DirectoryScanning.scan(url)
        puts Colorize.green("Found #{found.length} paths")
        @reporter.add_result("Directory Scan", found)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist_path = gets.chomp
        wordlist = wordlist_path.empty? ? nil : File.readlines(wordlist_path).map(&:chomp)
        found = DirectoryScanning.scan(url, wordlist)
        puts Colorize.green("Found #{found.length} paths")
        @reporter.add_result("Full Directory Scan", found)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter extensions (comma-separated): ")
        extensions = gets.chomp.split(',')
        found = DirectoryScanning.scan(url, nil, extensions)
        puts Colorize.green("Found #{found.length} paths")
        @reporter.add_result("Directory Scan with Extensions", found)
        pause
      when 0 then return
      end
    end
  end

  def ssl_analysis_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Check Certificate")
      puts Colorize.yellow("  [2]  Analyze Protocols")
      puts Colorize.yellow("  [3]  Check Heartbleed")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 443): ")
        port = gets.chomp.to_i
        port = 443 if port == 0
        result = SSLAnalysis.check_certificate(host, port)
        if result
          puts "Subject: #{result[:subject]}"
          puts "Issuer: #{result[:issuer]}"
          puts "Valid from: #{result[:not_before]}"
          puts "Valid until: #{result[:not_after]}"
          puts result[:expired] ? Colorize.red("Certificate expired!") : Colorize.green("Days left: #{result[:days_left]}")
        end
        @reporter.add_result("SSL Certificate", result)
        pause
      when 2
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        result = SSLAnalysis.analyze_protocols(host)
        result.each { |proto, supported| puts "#{proto}: #{supported ? 'Supported' : 'Not Supported'}" }
        @reporter.add_result("SSL Protocols", result)
        pause
      when 3
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        result = SSLAnalysis.check_heartbleed(host)
        puts result ? Colorize.red("Vulnerable to Heartbleed!") : Colorize.green("Not vulnerable")
        @reporter.add_result("Heartbleed Check", result)
        pause
      when 0 then return
      end
    end
  end

  def network_scanning_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Ping Sweep")
      puts Colorize.yellow("  [2]  Network Scan")
      puts Colorize.yellow("  [3]  Traceroute")
      puts Colorize.yellow("  [4]  Traffic Analysis")
      puts Colorize.yellow("  [5]  Firewall Detection")
      puts Colorize.yellow("  [6]  DNS Analysis")
      puts Colorize.yellow("  [7]  CDN Detection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter network (e.g., 192.168.1.0/24): ")
        network = gets.chomp
        puts Colorize.yellow("Ping sweep not fully implemented")
        pause
      when 2
        print Colorize.cyan("Enter network (e.g., 192.168.1.0/24): ")
        network = gets.chomp
        results = NetworkAnalysis.ping_sweep(network)
        puts Colorize.green("Found #{results.length} alive hosts")
        @reporter.add_result("Network Scan", results)
        pause
      when 3
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter max hops (default 30): ")
        max_hops = gets.chomp.to_i
        max_hops = 30 if max_hops == 0
        results = NetworkAnalysis.traceroute(host, max_hops)
        results.each { |r| puts "Hop #{r[:hop]}: #{r[:ip]}" }
        @reporter.add_result("Traceroute", results)
        pause
      when 4
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port: ")
        port = gets.chomp.to_i
        print Colorize.cyan("Enter duration (seconds, default 10): ")
        duration = gets.chomp.to_i
        duration = 10 if duration == 0
        results = NetworkAnalysis.analyze_traffic(host, port, duration)
        puts "Packets: #{results[:packets]}, Bytes: #{results[:bytes]}"
        @reporter.add_result("Traffic Analysis", results)
        pause
      when 5
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        results = NetworkAnalysis.detect_firewall(host)
        results.each { |port, data| puts "Port #{port}: #{data[:status]} (Firewall: #{data[:firewall]})" }
        @reporter.add_result("Firewall Detection", results)
        pause
      when 6
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        results = NetworkAnalysis.analyze_dns(domain)
        results.each { |type, data| puts "#{type}: #{data.join(', ')}" unless data.empty? }
        @reporter.add_result("DNS Analysis", results)
        pause
      when 7
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        cdns = NetworkAnalysis.detect_cdn(domain)
        puts cdns.any? ? Colorize.green("CDN detected: #{cdns.join(', ')}") : Colorize.yellow("No CDN detected")
        @reporter.add_result("CDN Detection", cdns)
        pause
      when 0 then return
      end
    end
  end

  def cryptography_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Hash Text")
      puts Colorize.yellow("  [2]  Encrypt/Decrypt")
      puts Colorize.yellow("  [3]  Generate Key")
      puts Colorize.yellow("  [4]  Identify Hash")
      puts Colorize.yellow("  [5]  Base64 Encode/Decode")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter text: ")
        text = gets.chomp
        hashes = Cryptography.hash(text)
        hashes.each { |algo, hash| puts "#{algo}: #{hash}" }
        @reporter.add_result("Hashing", hashes)
        pause
      when 2
        print Colorize.cyan("  [1]  Encrypt  [2]  Decrypt: ")
        op = gets.chomp.to_i
        print Colorize.cyan("Enter text: ")
        text = gets.chomp
        print Colorize.cyan("Enter key: ")
        key = gets.chomp
        if op == 1
          result = Cryptography.encrypt(text, key)
          puts Colorize.green("Encrypted: #{result}")
        else
          result = Cryptography.decrypt(text, key)
          puts Colorize.green("Decrypted: #{result}")
        end
        @reporter.add_result("Encryption", result)
        pause
      when 3
        print Colorize.cyan("Enter key length: ")
        length = gets.chomp.to_i
        key = Cryptography.generate_key(length)
        puts Colorize.green("Key: #{key}")
        @reporter.add_result("Key Generation", key)
        pause
      when 4
        print Colorize.cyan("Enter hash: ")
        hash = gets.chomp
        type = Cryptography.identify_hash(hash)
        puts Colorize.green("Hash type: #{type}")
        @reporter.add_result("Hash Identification", type)
        pause
      when 5
        print Colorize.cyan("  [1]  Encode  [2]  Decode: ")
        op = gets.chomp.to_i
        print Colorize.cyan("Enter text: ")
        text = gets.chomp
        if op == 1
          result = Cryptography.base64_encode(text)
          puts Colorize.green("Encoded: #{result}")
        else
          result = Cryptography.base64_decode(text)
          puts Colorize.green("Decoded: #{result}")
        end
        @reporter.add_result("Base64", result)
        pause
      when 0 then return
      end
    end
  end

  def exploits_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Payload")
      puts Colorize.yellow("  [2]  Search Exploits")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        puts Colorize.cyan("  [1]  PHP  [2]  Python  [3]  Bash  [4]  PowerShell  [5]  Perl  [6]  Ruby  [7]  NC  [8]  Java: ")
        type_choice = gets.chomp.to_i
        types = { 1 => :php, 2 => :python, 3 => :bash, 4 => :powershell, 5 => :perl, 6 => :ruby, 7 => :nc, 8 => :java }
        type = types[type_choice]
        if type
          print Colorize.cyan("Enter IP: ")
          ip = gets.chomp
          print Colorize.cyan("Enter port: ")
          port = gets.chomp
          payload = Exploits.generate_payload(type, ip, port)
          if payload
            puts Colorize.green("Payload:")
            puts payload
            filename = Exploits.save_payload(payload)
            puts Colorize.green("Saved: #{filename}")
            @reporter.add_result("Payload Generation", { type: type, payload: payload })
          end
        end
        pause
      when 2
        print Colorize.cyan("Enter software name: ")
        software = gets.chomp
        links = Exploits.search_exploits(software)
        links.each { |site, url| puts "#{site}: #{url}" }
        @reporter.add_result("Exploit Search", links)
        pause
      when 0 then return
      end
    end
  end

  def reporting_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Export JSON")
      puts Colorize.yellow("  [2]  Export CSV")
      puts Colorize.yellow("  [3]  Export Markdown")
      puts Colorize.yellow("  [4]  View Results")
      puts Colorize.yellow("  [5]  Clear Results")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        filename = @reporter.export_json("#{filename}.json")
        puts Colorize.green("Exported: #{filename}")
        pause
      when 2
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        filename = @reporter.export_csv("#{filename}.csv")
        puts Colorize.green("Exported: #{filename}")
        pause
      when 3
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        print Colorize.cyan("Enter title: ")
        title = gets.chomp
        filename = @reporter.export_markdown("#{filename}.md", title)
        puts Colorize.green("Exported: #{filename}")
        pause
      when 4
        results = @reporter.view_results
        if results.empty?
          puts Colorize.cyan("No results")
        else
          results.each_with_index do |result, i|
            puts "#{i+1}. [#{result[:type]}] #{result[:timestamp]}"
          end
        end
        pause
      when 5
        @reporter.clear
        puts Colorize.green("Results cleared")
        pause
      when 0 then return
      end
    end
  end

  def fuzzing_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Fuzz Parameters")
      puts Colorize.yellow("  [2]  Fuzz Paths")
      puts Colorize.yellow("  [3]  Fuzz Headers")
      puts Colorize.yellow("  [4]  Fuzz HTTP Methods")
      puts Colorize.yellow("  [5]  Fuzz Values")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist_path = gets.chomp
        wordlist = wordlist_path.empty? ? nil : File.readlines(wordlist_path).map(&:chomp)
        results = Fuzzing.fuzz_parameters(url, wordlist)
        @reporter.add_result("Parameter Fuzzing", results)
        pause
      when 2
        print Colorize.cyan("Enter base URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist_path = gets.chomp
        wordlist = wordlist_path.empty? ? nil : File.readlines(wordlist_path).map(&:chomp)
        results = Fuzzing.fuzz_paths(url, wordlist)
        @reporter.add_result("Path Fuzzing", results)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist_path = gets.chomp
        wordlist = wordlist_path.empty? ? nil : File.readlines(wordlist_path).map(&:chomp)
        results = Fuzzing.fuzz_headers(url, wordlist)
        @reporter.add_result("Header Fuzzing", results)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        results = Fuzzing.fuzz_methods(url)
        @reporter.add_result("Method Fuzzing", results)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name: ")
        param = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist_path = gets.chomp
        wordlist = wordlist_path.empty? ? nil : File.readlines(wordlist_path).map(&:chomp)
        results = Fuzzing.fuzz_values(url, param, wordlist)
        @reporter.add_result("Value Fuzzing", results)
        pause
      when 0 then return
      end
    end
  end

  def api_testing_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Endpoint")
      puts Colorize.yellow("  [2]  Test Authentication")
      puts Colorize.yellow("  [3]  Test Rate Limiting")
      puts Colorize.yellow("  [4]  Test CORS")
      puts Colorize.yellow("  [5]  Test JSON Injection")
      puts Colorize.yellow("  [6]  Test XML Injection")
      puts Colorize.yellow("  [7]  Test Parameter Pollution")
      puts Colorize.yellow("  [8]  Test IDOR")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter method (GET/POST/PUT/DELETE): ")
        method = gets.chomp.downcase.to_sym
        result = APITesting.test_endpoint(url, method)
        puts "Status: #{result[:status]}" if result
        @reporter.add_result("API Endpoint Test", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        puts Colorize.cyan("  [1]  Basic  [2]  Bearer  [3]  API Key  [4]  Custom: ")
        auth_type = gets.chomp.to_i
        types = { 1 => 'basic', 2 => 'bearer', 3 => 'apikey', 4 => 'custom' }
        type = types[auth_type]
        if type == 'basic'
          print Colorize.cyan("Enter username: ")
          username = gets.chomp
          print Colorize.cyan("Enter password: ")
          password = gets.chomp
          result = APITesting.test_authentication(url, type, { username: username, password: password })
        elsif type == 'bearer'
          print Colorize.cyan("Enter token: ")
          token = gets.chomp
          result = APITesting.test_authentication(url, type, { token: token })
        elsif type == 'apikey'
          print Colorize.cyan("Enter API key: ")
          key = gets.chomp
          result = APITesting.test_authentication(url, type, { key: key })
        end
        @reporter.add_result("API Authentication Test", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter number of requests: ")
        requests = gets.chomp.to_i
        result = APITesting.test_rate_limiting(url, requests)
        puts "Requests: #{result[:total_requests]}, RPS: #{result[:requests_per_second]}" if result
        @reporter.add_result("Rate Limiting Test", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = APITesting.test_cors(url)
        puts result[:vulnerable] ? Colorize.red("CORS vulnerable!") : Colorize.green("CORS secure")
        @reporter.add_result("CORS Test", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter JSON payload: ")
        payload = gets.chomp
        result = APITesting.test_json_injection(url, JSON.parse(payload) rescue payload)
        @reporter.add_result("JSON Injection Test", result)
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter XML payload: ")
        payload = gets.chomp
        result = APITesting.test_xml_injection(url, payload)
        @reporter.add_result("XML Injection Test", result)
        pause
      when 7
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name: ")
        param = gets.chomp
        print Colorize.cyan("Enter values (comma-separated): ")
        values = gets.chomp.split(',')
        result = APITesting.test_parameter_pollution(url, param, values)
        @reporter.add_result("Parameter Pollution Test", result)
        pause
      when 8
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter ID 1: ")
        id1 = gets.chomp
        print Colorize.cyan("Enter ID 2: ")
        id2 = gets.chomp
        result = APITesting.test_idor(url, id1, id2)
        puts result[:vulnerable] ? Colorize.red("IDOR vulnerable!") : Colorize.green("IDOR secure")
        @reporter.add_result("IDOR Test", result)
        pause
      when 0 then return
      end
    end
  end

  def wordlist_generator_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate from Base Word")
      puts Colorize.yellow("  [2]  Generate Common Passwords")
      puts Colorize.yellow("  [3]  Generate Date-based")
      puts Colorize.yellow("  [4]  Generate Permutations")
      puts Colorize.yellow("  [5]  Generate Leet Speak")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter base word: ")
        base = gets.chomp
        print Colorize.cyan("Min length (default 4): ")
        min = gets.chomp.to_i
        min = 4 if min == 0
        print Colorize.cyan("Max length (default 20): ")
        max = gets.chomp.to_i
        max = 20 if max == 0
        wordlist = WordlistGenerator.generate_from_base(base, min_length: min, max_length: max)
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        WordlistGenerator.save_wordlist(wordlist, filename)
        puts Colorize.green("Wordlist saved: #{filename} (#{wordlist.length} entries)")
        @reporter.add_result("Wordlist Generation", { filename: filename, count: wordlist.length })
        pause
      when 2
        print Colorize.cyan("Enter count (default 1000): ")
        count = gets.chomp.to_i
        count = 1000 if count == 0
        wordlist = WordlistGenerator.generate_common_passwords(count)
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        WordlistGenerator.save_wordlist(wordlist, filename)
        puts Colorize.green("Wordlist saved: #{filename} (#{wordlist.length} entries)")
        @reporter.add_result("Common Passwords", { filename: filename, count: wordlist.length })
        pause
      when 3
        print Colorize.cyan("Enter base word: ")
        base = gets.chomp
        print Colorize.cyan("Start year (default 1900): ")
        start = gets.chomp.to_i
        start = 1900 if start == 0
        print Colorize.cyan("End year (default 2024): ")
        end_year = gets.chomp.to_i
        end_year = 2024 if end_year == 0
        wordlist = WordlistGenerator.generate_date_based(base, start, end_year)
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        WordlistGenerator.save_wordlist(wordlist, filename)
        puts Colorize.green("Wordlist saved: #{filename} (#{wordlist.length} entries)")
        @reporter.add_result("Date-based Wordlist", { filename: filename, count: wordlist.length })
        pause
      when 4
        print Colorize.cyan("Enter words (comma-separated): ")
        words = gets.chomp.split(',')
        print Colorize.cyan("Max length (default 3): ")
        max = gets.chomp.to_i
        max = 3 if max == 0
        wordlist = WordlistGenerator.generate_permutations(words, max)
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        WordlistGenerator.save_wordlist(wordlist, filename)
        puts Colorize.green("Wordlist saved: #{filename} (#{wordlist.length} entries)")
        @reporter.add_result("Permutations", { filename: filename, count: wordlist.length })
        pause
      when 5
        print Colorize.cyan("Enter word: ")
        word = gets.chomp
        wordlist = WordlistGenerator.generate_leet_speak(word)
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        WordlistGenerator.save_wordlist(wordlist, filename)
        puts Colorize.green("Wordlist saved: #{filename} (#{wordlist.length} entries)")
        @reporter.add_result("Leet Speak", { filename: filename, count: wordlist.length })
        pause
      when 0 then return
      end
    end
  end

  def automation_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Full Web Scan")
      puts Colorize.yellow("  [2]  Full Port Scan")
      puts Colorize.yellow("  [3]  Reconnaissance")
      puts Colorize.yellow("  [4]  Vulnerability Assessment")
      puts Colorize.yellow("  [5]  Scheduled Scan")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        results = Automation.full_web_scan(url)
        @reporter.add_result("Full Web Scan", results)
        pause
      when 2
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter ports (comma-separated, or 'all' for all): ")
        ports_input = gets.chomp
        ports = ports_input == 'all' ? nil : ports_input.split(',').map(&:to_i)
        results = Automation.full_port_scan(host, ports)
        @reporter.add_result("Full Port Scan", results)
        pause
      when 3
        print Colorize.cyan("Enter target: ")
        target = gets.chomp
        results = Automation.reconnaissance(target)
        @reporter.add_result("Reconnaissance", results)
        pause
      when 4
        print Colorize.cyan("Enter target: ")
        target = gets.chomp
        results = Automation.vulnerability_assessment(target)
        @reporter.add_result("Vulnerability Assessment", results)
        pause
      when 5
        print Colorize.cyan("Enter target: ")
        target = gets.chomp
        print Colorize.cyan("Enter interval in seconds (default 3600): ")
        interval = gets.chomp.to_i
        interval = 3600 if interval == 0
        puts Colorize.yellow("Starting scheduled scan (Ctrl+C to stop)")
        Automation.scheduled_scan(target, interval)
      when 0 then return
      end
    end
  end

  def session_management_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Session Fixation")
      puts Colorize.yellow("  [2]  Test Session Timeout")
      puts Colorize.yellow("  [3]  Test Session Hijacking")
      puts Colorize.yellow("  [4]  Test Concurrent Sessions")
      puts Colorize.yellow("  [5]  Test Session Regeneration")
      puts Colorize.yellow("  [6]  Test CSRF Protection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = SessionManagement.test_session_fixation(url)
        puts result[:vulnerable] ? Colorize.red("Session fixation vulnerable!") : Colorize.green("Session fixation protected")
        @reporter.add_result("Session Fixation", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter delay in seconds (default 3600): ")
        delay = gets.chomp.to_i
        delay = 3600 if delay == 0
        result = SessionManagement.test_session_timeout(url, delay)
        @reporter.add_result("Session Timeout", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter session ID: ")
        session_id = gets.chomp
        result = SessionManagement.test_session_hijacking(url, session_id)
        puts result[:authenticated] ? Colorize.red("Session hijacking possible!") : Colorize.green("Session secure")
        @reporter.add_result("Session Hijacking", result)
        pause
      when 4
        print Colorize.cyan("Enter login URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter username: ")
        username = gets.chomp
        print Colorize.cyan("Enter password: ")
        password = gets.chomp
        result = SessionManagement.test_concurrent_sessions(url, username, password)
        puts result[:concurrent_allowed] ? Colorize.yellow("Concurrent sessions allowed") : Colorize.green("Concurrent sessions not allowed")
        @reporter.add_result("Concurrent Sessions", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = SessionManagement.test_session_regeneration(url)
        puts result[:regenerated] ? Colorize.green("Session regenerated") : Colorize.red("Session not regenerated")
        @reporter.add_result("Session Regeneration", result)
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = SessionManagement.test_csrf(url)
        puts result[:csrf_protected] ? Colorize.green("CSRF protection found") : Colorize.red("No CSRF protection")
        @reporter.add_result("CSRF Protection", result)
        pause
      when 0 then return
      end
    end
  end

  def file_upload_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test File Upload")
      puts Colorize.yellow("  [2]  Test MIME Bypass")
      puts Colorize.yellow("  [3]  Test Double Extension")
      puts Colorize.yellow("  [4]  Test Null Byte")
      puts Colorize.yellow("  [5]  Test Path Traversal")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter upload URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter field name (default 'file'): ")
        field = gets.chomp
        field = 'file' if field.empty?
        results = FileUpload.test_file_upload(url, field)
        @reporter.add_result("File Upload", results)
        pause
      when 2
        print Colorize.cyan("Enter upload URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter field name (default 'file'): ")
        field = gets.chomp
        field = 'file' if field.empty?
        results = FileUpload.test_mime_bypass(url, field)
        @reporter.add_result("MIME Bypass", results)
        pause
      when 3
        print Colorize.cyan("Enter upload URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter field name (default 'file'): ")
        field = gets.chomp
        field = 'file' if field.empty?
        results = FileUpload.test_double_extension(url, field)
        @reporter.add_result("Double Extension", results)
        pause
      when 4
        print Colorize.cyan("Enter upload URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter field name (default 'file'): ")
        field = gets.chomp
        field = 'file' if field.empty?
        results = FileUpload.test_null_byte(url, field)
        @reporter.add_result("Null Byte Bypass", results)
        pause
      when 5
        print Colorize.cyan("Enter upload URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter field name (default 'file'): ")
        field = gets.chomp
        field = 'file' if field.empty?
        result = FileUpload.test_path_traversal(url, field)
        @reporter.add_result("Path Traversal Upload", result)
        pause
      when 0 then return
      end
    end
  end

  def xxe_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test XXE")
      puts Colorize.yellow("  [2]  Test Blind XXE")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = XXE.test_xxe(url)
        puts result ? Colorize.red("XXE vulnerability found!") : Colorize.green("No XXE vulnerability")
        @reporter.add_result("XXE Test", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter external server: ")
        server = gets.chomp
        result = XXE.test_blind_xxe(url, server)
        puts result[:sent] ? Colorize.yellow("Blind XXE payload sent") : Colorize.red("Failed to send")
        @reporter.add_result("Blind XXE", result)
        pause
      when 0 then return
      end
    end
  end

  def ssrf_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test SSRF")
      puts Colorize.yellow("  [2]  Test Blind SSRF")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'url'): ")
        param = gets.chomp
        param = 'url' if param.empty?
        result = SSRF.test_ssrf(url, param)
        puts result ? Colorize.red("SSRF vulnerability found!") : Colorize.green("No SSRF vulnerability")
        @reporter.add_result("SSRF Test", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'url'): ")
        param = gets.chomp
        param = 'url' if param.empty?
        print Colorize.cyan("Enter external server: ")
        server = gets.chomp
        result = SSRF.test_blind_ssrf(url, param, server)
        puts result[:sent] ? Colorize.yellow("Blind SSRF payload sent") : Colorize.red("Failed to send")
        @reporter.add_result("Blind SSRF", result)
        pause
      when 0 then return
      end
    end
  end

  def waf_bypass_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test SQLi Bypass")
      puts Colorize.yellow("  [2]  Test XSS Bypass")
      puts Colorize.yellow("  [3]  Test Encoding Bypass")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WAFBypass.test_sqli_bypass(url)
        puts result ? Colorize.red("WAF bypass successful!") : Colorize.green("WAF protected")
        @reporter.add_result("WAF SQLi Bypass", result)
        @logger.info("WAF SQLi Bypass test", { url: url, result: result })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = WAFBypass.test_xss_bypass(url)
        puts result ? Colorize.red("WAF bypass successful!") : Colorize.green("WAF protected")
        @reporter.add_result("WAF XSS Bypass", result)
        @logger.info("WAF XSS Bypass test", { url: url, result: result })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter payload: ")
        payload = gets.chomp
        result = WAFBypass.test_encoding_bypass(url, payload)
        @reporter.add_result("Encoding Bypass", result)
        @logger.info("Encoding Bypass test", { url: url, payload: payload, result: result })
        pause
      when 0 then return
      end
    end
  end

  def advanced_recon_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Shodan Search")
      puts Colorize.yellow("  [2]  Censys Search")
      puts Colorize.yellow("  [3]  VirusTotal Domain")
      puts Colorize.yellow("  [4]  VirusTotal IP")
      puts Colorize.yellow("  [5]  Have I Been Pwned")
      puts Colorize.yellow("  [6]  Wayback Machine")
      puts Colorize.yellow("  [7]  Certificate Transparency")
      puts Colorize.yellow("  [8]  DNS Dumpster")
      puts Colorize.yellow("  [9]  Security Headers Scan")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        print Colorize.cyan("Enter Shodan API key: ")
        api_key = gets.chomp
        result = AdvancedRecon.shodan_search(query, api_key)
        puts result ? Colorize.green("Results found") : Colorize.red("No results")
        @reporter.add_result("Shodan Search", result)
        @logger.info("Shodan search", { query: query })
        pause
      when 2
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        print Colorize.cyan("Enter Censys API ID: ")
        api_id = gets.chomp
        print Colorize.cyan("Enter Censys API Secret: ")
        api_secret = gets.chomp
        result = AdvancedRecon.censys_search(query, api_id, api_secret)
        puts result ? Colorize.green("Results found") : Colorize.red("No results")
        @reporter.add_result("Censys Search", result)
        @logger.info("Censys search", { query: query })
        pause
      when 3
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        print Colorize.cyan("Enter VirusTotal API key: ")
        api_key = gets.chomp
        result = AdvancedRecon.virustotal_domain(domain, api_key)
        puts result ? Colorize.green("Results found") : Colorize.red("No results")
        @reporter.add_result("VirusTotal Domain", result)
        @logger.info("VirusTotal domain check", { domain: domain })
        pause
      when 4
        print Colorize.cyan("Enter IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter VirusTotal API key: ")
        api_key = gets.chomp
        result = AdvancedRecon.virustotal_ip(ip, api_key)
        puts result ? Colorize.green("Results found") : Colorize.red("No results")
        @reporter.add_result("VirusTotal IP", result)
        @logger.info("VirusTotal IP check", { ip: ip })
        pause
      when 5
        print Colorize.cyan("Enter email: ")
        email = gets.chomp
        print Colorize.cyan("Enter API key (optional): ")
        api_key = gets.chomp
        result = AdvancedRecon.haveibeenpwned(email, api_key)
        if result
          puts result[:pwned] ? Colorize.red("Email pwned #{result[:count]} times!") : Colorize.green("Email not pwned")
        end
        @reporter.add_result("Have I Been Pwned", result)
        @logger.info("Have I Been Pwned check", { email: email })
        pause
      when 6
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        results = AdvancedRecon.wayback_machine(domain)
        puts Colorize.green("Found #{results.length} URLs")
        @reporter.add_result("Wayback Machine", results)
        @logger.info("Wayback Machine search", { domain: domain, count: results.length })
        pause
      when 7
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        results = AdvancedRecon.certificate_transparency(domain)
        puts Colorize.green("Found #{results.length} subdomains")
        @reporter.add_result("Certificate Transparency", results)
        @logger.info("Certificate Transparency search", { domain: domain, count: results.length })
        pause
      when 8
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        results = AdvancedRecon.dns_dumpster(domain)
        puts Colorize.green("Found #{results.length} subdomains")
        @reporter.add_result("DNS Dumpster", results)
        @logger.info("DNS Dumpster search", { domain: domain, count: results.length })
        pause
      when 9
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = AdvancedRecon.security_headers_scan(url)
        if result
          puts "Security Score: #{result[:score]}%"
          result[:security_headers].each { |k, v| puts "#{k}: #{v || 'Missing'}" }
        end
        @reporter.add_result("Security Headers Scan", result)
        @logger.info("Security headers scan", { url: url, score: result[:score] })
        pause
      when 0 then return
      end
    end
  end

  def payload_generator_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Reverse Shell")
      puts Colorize.yellow("  [2]  Generate Bind Shell")
      puts Colorize.yellow("  [3]  Generate Web Shell")
      puts Colorize.yellow("  [4]  Generate Obfuscated Payload")
      puts Colorize.yellow("  [5]  Generate Polyglot Payload")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port: ")
        port = gets.chomp
        puts Colorize.cyan("  [1]  Bash  [2]  Python  [3]  Perl  [4]  Ruby  [5]  PHP  [6]  NC  [7]  Socat: ")
        shell_type = gets.chomp.to_i
        types = { 1 => :bash, 2 => :python, 3 => :perl, 4 => :ruby, 5 => :php, 6 => :nc, 7 => :socat }
        type = types[shell_type] || :bash
        payload = PayloadGenerator.generate_reverse_shell(ip, port, type)
        puts Colorize.green("Payload:")
        puts payload
        filename = "reverse_shell_#{Time.now.to_i}.txt"
        File.write(filename, payload)
        puts Colorize.green("Saved: #{filename}")
        @reporter.add_result("Reverse Shell", { type: type, payload: payload })
        @logger.info("Reverse shell generated", { type: type, ip: ip, port: port })
        pause
      when 2
        print Colorize.cyan("Enter port: ")
        port = gets.chomp
        puts Colorize.cyan("  [1]  Bash  [2]  Python  [3]  Perl  [4]  Ruby  [5]  PHP  [6]  NC  [7]  Socat: ")
        shell_type = gets.chomp.to_i
        types = { 1 => :bash, 2 => :python, 3 => :perl, 4 => :ruby, 5 => :php, 6 => :nc, 7 => :socat }
        type = types[shell_type] || :bash
        payload = PayloadGenerator.generate_bind_shell(port, type)
        puts Colorize.green("Payload:")
        puts payload
        filename = "bind_shell_#{Time.now.to_i}.txt"
        File.write(filename, payload)
        puts Colorize.green("Saved: #{filename}")
        @reporter.add_result("Bind Shell", { type: type, payload: payload })
        @logger.info("Bind shell generated", { type: type, port: port })
        pause
      when 3
        puts Colorize.cyan("  [1]  PHP  [2]  JSP  [3]  ASP  [4]  ASPX  [5]  CGI  [6]  Perl  [7]  Python  [8]  Ruby: ")
        shell_type = gets.chomp.to_i
        types = { 1 => :php, 2 => :jsp, 3 => :asp, 4 => :aspx, 5 => :cgi, 6 => :perl, 7 => :python, 8 => :ruby }
        type = types[shell_type] || :php
        payload = PayloadGenerator.generate_web_shell(type)
        puts Colorize.green("Payload:")
        puts payload
        filename = "web_shell_#{type}_#{Time.now.to_i}.txt"
        File.write(filename, payload)
        puts Colorize.green("Saved: #{filename}")
        @reporter.add_result("Web Shell", { type: type, payload: payload })
        @logger.info("Web shell generated", { type: type })
        pause
      when 4
        print Colorize.cyan("Enter payload: ")
        payload = gets.chomp
        puts Colorize.cyan("  [1]  Base64  [2]  Hex  [3]  URL  [4]  Unicode  [5]  ROT13  [6]  XOR: ")
        obf_type = gets.chomp.to_i
        types = { 1 => :base64, 2 => :hex, 3 => :url, 4 => :unicode, 5 => :rot13, 6 => :xor }
        type = types[obf_type] || :base64
        obfuscated = PayloadGenerator.generate_obfuscated_payload(payload, type)
        puts Colorize.green("Obfuscated payload:")
        puts obfuscated
        filename = "obfuscated_#{Time.now.to_i}.txt"
        File.write(filename, obfuscated)
        puts Colorize.green("Saved: #{filename}")
        @reporter.add_result("Obfuscated Payload", { type: type, payload: obfuscated })
        @logger.info("Payload obfuscated", { type: type })
        pause
      when 5
        payloads = PayloadGenerator.generate_polyglot_payload
        payloads.each_with_index do |payload, i|
          puts "#{i+1}. #{payload}"
        end
        filename = "polyglot_#{Time.now.to_i}.txt"
        File.write(filename, payloads.join("\n"))
        puts Colorize.green("Saved: #{filename}")
        @reporter.add_result("Polyglot Payloads", payloads)
        @logger.info("Polyglot payloads generated", { count: payloads.length })
        pause
      when 0 then return
      end
    end
  end

  def deserialization_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Java Deserialization")
      puts Colorize.yellow("  [2]  Test PHP Deserialization")
      puts Colorize.yellow("  [3]  Test Python Deserialization")
      puts Colorize.yellow("  [4]  Test Ruby Deserialization")
      puts Colorize.yellow("  [5]  Test All")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Deserialization.test_java_deserialization(url)
        @reporter.add_result("Java Deserialization", result)
        @logger.info("Java deserialization test", { url: url })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Deserialization.test_php_deserialization(url)
        @reporter.add_result("PHP Deserialization", result)
        @logger.info("PHP deserialization test", { url: url })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Deserialization.test_python_deserialization(url)
        @reporter.add_result("Python Deserialization", result)
        @logger.info("Python deserialization test", { url: url })
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Deserialization.test_ruby_deserialization(url)
        @reporter.add_result("Ruby Deserialization", result)
        @logger.info("Ruby deserialization test", { url: url })
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Deserialization.test_all(url)
        @reporter.add_result("All Deserialization", result)
        @logger.info("All deserialization test", { url: url })
        pause
      when 0 then return
      end
    end
  end

  def race_condition_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test TOCTOU")
      puts Colorize.yellow("  [2]  Test Parallel Requests")
      puts Colorize.yellow("  [3]  Test Concurrent Modification")
      puts Colorize.yellow("  [4]  Test Idempotency")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter number of requests (default 100): ")
        requests = gets.chomp.to_i
        requests = 100 if requests == 0
        result = RaceCondition.test_time_of_check_time_of_use(url, requests)
        @reporter.add_result("TOCTOU", result)
        @logger.info("TOCTOU test", { url: url, requests: requests })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter number of parallel requests (default 50): ")
        count = gets.chomp.to_i
        count = 50 if count == 0
        result = RaceCondition.test_parallel_requests(url, count)
        puts "Average time: #{result[:avg_time]}s"
        @reporter.add_result("Parallel Requests", result)
        @logger.info("Parallel requests test", { url: url, count: count })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name: ")
        param = gets.chomp
        print Colorize.cyan("Enter value: ")
        value = gets.chomp
        result = RaceCondition.test_concurrent_modification(url, param, value)
        @reporter.add_result("Concurrent Modification", result)
        @logger.info("Concurrent modification test", { url: url, param: param })
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        puts Colorize.cyan("  [1]  POST  [2]  PUT  [3]  DELETE: ")
        method_choice = gets.chomp.to_i
        methods = { 1 => :post, 2 => :put, 3 => :delete }
        method = methods[method_choice] || :post
        result = RaceCondition.test_idempotency(url, method)
        puts result[:idempotent] ? Colorize.green("Idempotent") : Colorize.red("Not idempotent")
        @reporter.add_result("Idempotency", result)
        @logger.info("Idempotency test", { url: url, method: method })
        pause
      when 0 then return
      end
    end
  end

  def business_logic_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Price Manipulation")
      puts Colorize.yellow("  [2]  Test Quantity Manipulation")
      puts Colorize.yellow("  [3]  Test Workflow Bypass")
      puts Colorize.yellow("  [4]  Test Privilege Escalation")
      puts Colorize.yellow("  [5]  Test Authorization Bypass")
      puts Colorize.yellow("  [6]  Test Payment Bypass")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter product ID: ")
        product_id = gets.chomp
        print Colorize.cyan("Enter original price: ")
        price = gets.chomp.to_f
        result = BusinessLogic.test_price_manipulation(url, product_id, price)
        @reporter.add_result("Price Manipulation", result)
        @logger.info("Price manipulation test", { url: url, product_id: product_id })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter product ID: ")
        product_id = gets.chomp
        print Colorize.cyan("Enter max quantity: ")
        max_qty = gets.chomp.to_i
        result = BusinessLogic.test_quantity_manipulation(url, product_id, max_qty)
        @reporter.add_result("Quantity Manipulation", result)
        @logger.info("Quantity manipulation test", { url: url, product_id: product_id })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter current step: ")
        current = gets.chomp
        print Colorize.cyan("Enter target step: ")
        target = gets.chomp
        result = BusinessLogic.test_workflow_bypass(url, current, target)
        @reporter.add_result("Workflow Bypass", result)
        @logger.info("Workflow bypass test", { url: url })
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter current role: ")
        current = gets.chomp
        print Colorize.cyan("Enter target role: ")
        target = gets.chomp
        result = BusinessLogic.test_privilege_escalation(url, current, target)
        @reporter.add_result("Privilege Escalation", result)
        @logger.info("Privilege escalation test", { url: url })
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter user ID: ")
        user_id = gets.chomp
        print Colorize.cyan("Enter target ID: ")
        target_id = gets.chomp
        result = BusinessLogic.test_authorization_bypass(url, user_id, target_id)
        @reporter.add_result("Authorization Bypass", result)
        @logger.info("Authorization bypass test", { url: url })
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = BusinessLogic.test_payment_bypass(url)
        @reporter.add_result("Payment Bypass", result)
        @logger.info("Payment bypass test", { url: url })
        pause
      when 0 then return
      end
    end
  end

  def template_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Jinja2")
      puts Colorize.yellow("  [2]  Test FreeMarker")
      puts Colorize.yellow("  [3]  Test Velocity")
      puts Colorize.yellow("  [4]  Test Smarty")
      puts Colorize.yellow("  [5]  Test Twig")
      puts Colorize.yellow("  [6]  Test All")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :jinja2)
        @reporter.add_result("Jinja2 Injection", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :freemarker)
        @reporter.add_result("FreeMarker Injection", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :velocity)
        @reporter.add_result("Velocity Injection", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :smarty)
        @reporter.add_result("Smarty Injection", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :twig)
        @reporter.add_result("Twig Injection", result)
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = TemplateInjection.test(url, :all)
        @reporter.add_result("All Template Injection", result)
        pause
      when 0 then return
      end
    end
  end

  def ldap_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test LDAP Injection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'username'): ")
        param = gets.chomp
        param = 'username' if param.empty?
        result = LDAPInjection.test(url, param)
        puts result ? Colorize.red("LDAP injection found!") : Colorize.green("No LDAP injection")
        @reporter.add_result("LDAP Injection", result)
        pause
      when 0 then return
      end
    end
  end

  def nosql_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test MongoDB Injection")
      puts Colorize.yellow("  [2]  Test CouchDB Injection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = NoSQLInjection.test(url, :mongo)
        puts result ? Colorize.red("MongoDB injection found!") : Colorize.green("No MongoDB injection")
        @reporter.add_result("MongoDB Injection", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = NoSQLInjection.test(url, :couchdb)
        puts result ? Colorize.red("CouchDB injection found!") : Colorize.green("No CouchDB injection")
        @reporter.add_result("CouchDB Injection", result)
        pause
      when 0 then return
      end
    end
  end

  def settings_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Set Target")
      puts Colorize.yellow("  [2]  Set Timeout")
      puts Colorize.yellow("  [3]  Set Threads")
      puts Colorize.yellow("  [4]  Show Settings")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target: ")
        @target = gets.chomp
        puts Colorize.green("Target set: #{@target}")
        @logger.info("Target set", { target: @target })
        pause
      when 2
        print Colorize.cyan("Enter timeout (seconds): ")
        @timeout = gets.chomp.to_i
        puts Colorize.green("Timeout set: #{@timeout}s")
        @logger.info("Timeout set", { timeout: @timeout })
        pause
      when 3
        print Colorize.cyan("Enter threads: ")
        @threads = gets.chomp.to_i
        puts Colorize.green("Threads set: #{@threads}")
        @logger.info("Threads set", { threads: @threads })
        pause
      when 4
        puts Colorize.cyan("Current settings:")
        puts "  Target: #{@target || 'not set'}"
        puts "  Timeout: #{@timeout}s"
        puts "  Threads: #{@threads}"
        pause
      when 0 then return
      end
    end
  end

  def pause
    print Colorize.cyan("\nPress Enter to continue...")
    gets
  end

  def exit_tool
    exit
  end
end

