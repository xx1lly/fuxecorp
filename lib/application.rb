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
require_relative 'modules/password_cracking'
require_relative 'modules/command_injection'
require_relative 'modules/path_traversal'
require_relative 'modules/rce'
require_relative 'modules/jwt_attacks'
require_relative 'modules/graphql_injection'
require_relative 'modules/websocket_attacks'
require_relative 'modules/cache_poisoning'
require_relative 'modules/http_smuggling'
require_relative 'modules/subdomain_takeover'
require_relative 'modules/dns_rebinding'
require_relative 'modules/prototype_pollution'
require_relative 'modules/authentication_bypass'
require_relative 'modules/idor'
require_relative 'modules/csrf'
require_relative 'modules/open_redirect'
require_relative 'modules/phishing'
require_relative 'modules/social_engineering'
require_relative 'modules/email_spoofing'
require_relative 'modules/malware_generator'
require_relative 'modules/credential_harvesting'
require_relative 'modules/clickjacking'
require_relative 'modules/mass_assignment'
require_relative 'modules/timing_attacks'
require_relative 'modules/padding_oracle'
require_relative 'modules/crlf_injection'
require_relative 'modules/insecure_random'
require_relative 'modules/insecure_deserialization'
require_relative 'modules/exploit_chains'
require_relative 'modules/lateral_movement'
require_relative 'modules/persistence'
require_relative 'modules/data_exfiltration'
require_relative 'modules/post_exploitation'
require_relative 'modules/evasion'
require_relative 'modules/zero_day'
require_relative 'modules/c2_framework'
require_relative 'modules/ransomware'
require_relative 'modules/botnet'
require_relative 'modules/crypto_mining'
require_relative 'modules/rootkit'
require_relative 'modules/memory_attacks'
require_relative 'modules/wireless_attacks'
require_relative 'modules/bluetooth_attacks'
require_relative 'modules/iot_attacks'
require_relative 'modules/mobile_attacks'
require_relative 'modules/cloud_attacks'
require_relative 'modules/container_attacks'
require 'json'
require 'securerandom'
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
      puts Colorize.yellow("  [30] Password Cracking")
      puts Colorize.yellow("  [31] Command Injection")
      puts Colorize.yellow("  [32] Path Traversal")
      puts Colorize.yellow("  [33] RCE Testing")
      puts Colorize.yellow("  [34] JWT Attacks")
      puts Colorize.yellow("  [35] GraphQL Injection")
      puts Colorize.yellow("  [36] WebSocket Attacks")
      puts Colorize.yellow("  [37] Cache Poisoning")
      puts Colorize.yellow("  [38] HTTP Request Smuggling")
      puts Colorize.yellow("  [39] Subdomain Takeover")
      puts Colorize.yellow("  [40] DNS Rebinding")
      puts Colorize.yellow("  [41] Prototype Pollution")
      puts Colorize.yellow("  [42] Authentication Bypass")
      puts Colorize.yellow("  [43] IDOR Testing")
      puts Colorize.yellow("  [44] CSRF Testing")
      puts Colorize.yellow("  [45] Open Redirect")
      puts Colorize.yellow("  [46] Phishing")
      puts Colorize.yellow("  [47] Social Engineering")
      puts Colorize.yellow("  [48] Email Spoofing")
      puts Colorize.yellow("  [49] Malware Generator")
      puts Colorize.yellow("  [50] Credential Harvesting")
      puts Colorize.yellow("  [51] Clickjacking")
      puts Colorize.yellow("  [52] Mass Assignment")
      puts Colorize.yellow("  [53] Timing Attacks")
      puts Colorize.yellow("  [54] Padding Oracle")
      puts Colorize.yellow("  [55] CRLF Injection")
      puts Colorize.yellow("  [56] Insecure Random")
      puts Colorize.yellow("  [57] Insecure Deserialization")
      puts Colorize.yellow("  [58] Exploit Chains")
      puts Colorize.yellow("  [59] Lateral Movement")
      puts Colorize.yellow("  [60] Persistence")
      puts Colorize.yellow("  [61] Data Exfiltration")
      puts Colorize.yellow("  [62] Post Exploitation")
      puts Colorize.yellow("  [63] Evasion")
      puts Colorize.yellow("  [64] Zero-Day Exploits")
      puts Colorize.yellow("  [65] C2 Framework")
      puts Colorize.yellow("  [66] Ransomware")
      puts Colorize.yellow("  [67] Botnet")
      puts Colorize.yellow("  [68] Crypto Mining")
      puts Colorize.yellow("  [69] Rootkit")
      puts Colorize.yellow("  [70] Memory Attacks")
      puts Colorize.yellow("  [71] Wireless Attacks")
      puts Colorize.yellow("  [72] Bluetooth Attacks")
      puts Colorize.yellow("  [73] IoT Attacks")
      puts Colorize.yellow("  [74] Mobile Attacks")
      puts Colorize.yellow("  [75] Cloud Attacks")
      puts Colorize.yellow("  [76] Container Attacks")
      puts Colorize.yellow("  [77] Reporting")
      puts Colorize.yellow("  [78] Settings")
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
    when 30 then password_cracking_menu
    when 31 then command_injection_menu
    when 32 then path_traversal_menu
    when 33 then rce_menu
    when 34 then jwt_attacks_menu
    when 35 then graphql_injection_menu
    when 36 then websocket_attacks_menu
    when 37 then cache_poisoning_menu
    when 38 then http_smuggling_menu
    when 39 then subdomain_takeover_menu
    when 40 then dns_rebinding_menu
    when 41 then prototype_pollution_menu
    when 42 then authentication_bypass_menu
    when 43 then idor_menu
    when 44 then csrf_menu
    when 45 then open_redirect_menu
    when 46 then phishing_menu
    when 47 then social_engineering_menu
    when 48 then email_spoofing_menu
    when 49 then malware_generator_menu
    when 50 then credential_harvesting_menu
    when 51 then clickjacking_menu
    when 52 then mass_assignment_menu
    when 53 then timing_attacks_menu
    when 54 then padding_oracle_menu
    when 55 then crlf_injection_menu
    when 56 then insecure_random_menu
    when 57 then insecure_deserialization_menu
    when 58 then exploit_chains_menu
    when 59 then lateral_movement_menu
    when 60 then persistence_menu
    when 61 then data_exfiltration_menu
    when 62 then post_exploitation_menu
    when 63 then evasion_menu
    when 64 then zero_day_menu
    when 65 then c2_framework_menu
    when 66 then ransomware_menu
    when 67 then botnet_menu
    when 68 then crypto_mining_menu
    when 69 then rootkit_menu
    when 70 then memory_attacks_menu
    when 71 then wireless_attacks_menu
    when 72 then bluetooth_attacks_menu
    when 73 then iot_attacks_menu
    when 74 then mobile_attacks_menu
    when 75 then cloud_attacks_menu
    when 76 then container_attacks_menu
    when 77 then reporting_menu
    when 78 then settings_menu
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

  def password_cracking_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Crack Hash")
      puts Colorize.yellow("  [2]  Dictionary Attack")
      puts Colorize.yellow("  [3]  Bruteforce Mask")
      puts Colorize.yellow("  [4]  Generate Rainbow Table")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter hash: ")
        hash = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist = gets.chomp
        wordlist = nil if wordlist.empty?
        result = PasswordCracking.crack_hash(hash, wordlist)
        @reporter.add_result("Hash Cracking", { hash: hash, found: result })
        pause
      when 2
        print Colorize.cyan("Enter hash: ")
        hash = gets.chomp
        print Colorize.cyan("Enter dictionary path: ")
        dictionary = gets.chomp
        result = PasswordCracking.dictionary_attack(hash, dictionary)
        @reporter.add_result("Dictionary Attack", { hash: hash, found: result })
        pause
      when 3
        print Colorize.cyan("Enter mask (e.g., ????): ")
        mask = gets.chomp
        print Colorize.cyan("Enter charset (optional): ")
        charset = gets.chomp
        charset = charset.empty? ? nil : charset.chars
        results = PasswordCracking.bruteforce_mask(mask, charset)
        puts Colorize.green("Generated #{results.length} passwords")
        @reporter.add_result("Bruteforce Mask", { mask: mask, count: results.length })
        pause
      when 4
        print Colorize.cyan("Enter wordlist path: ")
        wordlist = gets.chomp
        print Colorize.cyan("Enter output file: ")
        output = gets.chomp
        PasswordCracking.generate_rainbow_table(wordlist, output)
        @reporter.add_result("Rainbow Table", { output: output })
        pause
      when 0 then return
      end
    end
  end

  def command_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Command Injection")
      puts Colorize.yellow("  [2]  Test Blind Command Injection")
      puts Colorize.yellow("  [3]  Test OS Detection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = CommandInjection.test(url, param)
        @reporter.add_result("Command Injection", { url: url, vulnerable: result })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        print Colorize.cyan("Enter callback URL (optional): ")
        callback = gets.chomp
        callback = nil if callback.empty?
        result = CommandInjection.test_blind(url, param, callback)
        @reporter.add_result("Blind Command Injection", { url: url, vulnerable: result })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = CommandInjection.test_os_command(url, param)
        @reporter.add_result("OS Detection", result)
        pause
      when 0 then return
      end
    end
  end

  def path_traversal_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Path Traversal")
      puts Colorize.yellow("  [2]  Test Absolute Path")
      puts Colorize.yellow("  [3]  Test Encoding Bypass")
      puts Colorize.yellow("  [4]  Test Null Byte Bypass")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'file'): ")
        param = gets.chomp
        param = 'file' if param.empty?
        result = PathTraversal.test(url, param)
        @reporter.add_result("Path Traversal", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'file'): ")
        param = gets.chomp
        param = 'file' if param.empty?
        result = PathTraversal.test_absolute_path(url, param)
        @reporter.add_result("Absolute Path", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'file'): ")
        param = gets.chomp
        param = 'file' if param.empty?
        result = PathTraversal.test_encoding_bypass(url, param)
        @reporter.add_result("Encoding Bypass", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'file'): ")
        param = gets.chomp
        param = 'file' if param.empty?
        result = PathTraversal.test_null_byte(url, param)
        @reporter.add_result("Null Byte Bypass", result)
        pause
      when 0 then return
      end
    end
  end

  def rce_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test PHP RCE")
      puts Colorize.yellow("  [2]  Test Python RCE")
      puts Colorize.yellow("  [3]  Test Ruby RCE")
      puts Colorize.yellow("  [4]  Test Java RCE")
      puts Colorize.yellow("  [5]  Test Template Injection RCE")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = RCE.test_php_rce(url, param)
        @reporter.add_result("PHP RCE", { url: url, vulnerable: result })
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = RCE.test_python_rce(url, param)
        @reporter.add_result("Python RCE", { url: url, vulnerable: result })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = RCE.test_ruby_rce(url, param)
        @reporter.add_result("Ruby RCE", { url: url, vulnerable: result })
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'cmd'): ")
        param = gets.chomp
        param = 'cmd' if param.empty?
        result = RCE.test_java_rce(url, param)
        @reporter.add_result("Java RCE", { url: url, vulnerable: result })
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'template'): ")
        param = gets.chomp
        param = 'template' if param.empty?
        result = RCE.test_template_injection_rce(url, param)
        @reporter.add_result("Template Injection RCE", result)
        pause
      when 0 then return
      end
    end
  end

  def jwt_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Decode JWT")
      puts Colorize.yellow("  [2]  Attack None Algorithm")
      puts Colorize.yellow("  [3]  Attack Weak Secret")
      puts Colorize.yellow("  [4]  Modify Payload")
      puts Colorize.yellow("  [5]  Escalate Privileges")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter JWT token: ")
        token = gets.chomp
        result = JWTAttacks.decode_jwt(token)
        if result
          puts "Header: #{result[:header]}"
          puts "Payload: #{result[:payload]}"
        end
        @reporter.add_result("JWT Decode", result)
        pause
      when 2
        print Colorize.cyan("Enter JWT token: ")
        token = gets.chomp
        result = JWTAttacks.attack_none_algorithm(token)
        @reporter.add_result("JWT None Algorithm", { token: result })
        pause
      when 3
        print Colorize.cyan("Enter JWT token: ")
        token = gets.chomp
        print Colorize.cyan("Enter wordlist path (optional): ")
        wordlist = gets.chomp
        wordlist = nil if wordlist.empty?
        result = JWTAttacks.attack_weak_secret(token, wordlist)
        @reporter.add_result("JWT Weak Secret", { secret: result })
        pause
      when 4
        print Colorize.cyan("Enter JWT token: ")
        token = gets.chomp
        print Colorize.cyan("Enter new payload (JSON): ")
        payload_json = gets.chomp
        payload = JSON.parse(payload_json) rescue { admin: true }
        result = JWTAttacks.modify_payload(token, payload)
        @reporter.add_result("JWT Modify Payload", { token: result })
        pause
      when 5
        print Colorize.cyan("Enter JWT token: ")
        token = gets.chomp
        result = JWTAttacks.escalate_privileges(token)
        @reporter.add_result("JWT Privilege Escalation", { token: result })
        pause
      when 0 then return
      end
    end
  end

  def graphql_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Introspection")
      puts Colorize.yellow("  [2]  Test SQL Injection")
      puts Colorize.yellow("  [3]  Test Field Duplication")
      puts Colorize.yellow("  [4]  Test Aliases")
      puts Colorize.yellow("  [5]  Test Batch Queries")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter GraphQL endpoint URL: ")
        url = gets.chomp
        result = GraphQLInjection.test_introspection(url)
        @reporter.add_result("GraphQL Introspection", result)
        pause
      when 2
        print Colorize.cyan("Enter GraphQL endpoint URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        result = GraphQLInjection.test_sqli(url, query)
        @reporter.add_result("GraphQL SQLi", { vulnerable: result })
        pause
      when 3
        print Colorize.cyan("Enter GraphQL endpoint URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        result = GraphQLInjection.test_field_duplication(url, query)
        @reporter.add_result("GraphQL Field Duplication", result)
        pause
      when 4
        print Colorize.cyan("Enter GraphQL endpoint URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        result = GraphQLInjection.test_aliases(url, query)
        @reporter.add_result("GraphQL Aliases", result)
        pause
      when 5
        print Colorize.cyan("Enter GraphQL endpoint URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter query: ")
        query = gets.chomp
        result = GraphQLInjection.test_batch_queries(url, query)
        @reporter.add_result("GraphQL Batch Queries", result)
        pause
      when 0 then return
      end
    end
  end

  def websocket_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test WebSocket Connection")
      puts Colorize.yellow("  [2]  Test Message Injection")
      puts Colorize.yellow("  [3]  Test CSWSH")
      puts Colorize.yellow("  [4]  Test DoS")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter WebSocket URL (ws:// or wss://): ")
        url = gets.chomp
        result = WebSocketAttacks.test_websocket(url)
        @reporter.add_result("WebSocket Connection", result)
        pause
      when 2
        print Colorize.cyan("Enter WebSocket URL: ")
        url = gets.chomp
        result = WebSocketAttacks.test_websocket(url)
        message = nil
        response = nil
        if result[:connected]
          print Colorize.cyan("Enter message to inject: ")
          message = gets.chomp
          response = WebSocketAttacks.test_message_injection(result[:socket], message)
          puts "Response: #{response}"
          result[:socket].close rescue nil
        end
        @reporter.add_result("WebSocket Message Injection", { message: message, response: response })
        pause
      when 3
        print Colorize.cyan("Enter WebSocket URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter malicious origin: ")
        origin = gets.chomp
        result = WebSocketAttacks.test_cross_site_websocket_hijacking(url, origin)
        @reporter.add_result("CSWSH", result)
        pause
      when 4
        print Colorize.cyan("Enter WebSocket URL: ")
        url = gets.chomp
        result = WebSocketAttacks.test_denial_of_service(url)
        @reporter.add_result("WebSocket DoS", result)
        pause
      when 0 then return
      end
    end
  end

  def cache_poisoning_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Host Header Injection")
      puts Colorize.yellow("  [2]  Test Cache Key Manipulation")
      puts Colorize.yellow("  [3]  Test Unkeyed Headers")
      puts Colorize.yellow("  [4]  Test Parameter Pollution")
      puts Colorize.yellow("  [5]  Test Cache Deception")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CachePoisoning.test_host_header_injection(url)
        @reporter.add_result("Host Header Injection", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CachePoisoning.test_cache_key_manipulation(url)
        @reporter.add_result("Cache Key Manipulation", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CachePoisoning.test_unkeyed_headers(url)
        @reporter.add_result("Unkeyed Headers", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CachePoisoning.test_parameter_pollution(url)
        @reporter.add_result("Parameter Pollution", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CachePoisoning.test_cache_deception(url)
        @reporter.add_result("Cache Deception", result)
        pause
      when 0 then return
      end
    end
  end

  def http_smuggling_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test CL.TE")
      puts Colorize.yellow("  [2]  Test TE.CL")
      puts Colorize.yellow("  [3]  Test TE.TE")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = HTTPSmuggling.test_cl_te(url)
        @reporter.add_result("HTTP Smuggling CL.TE", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = HTTPSmuggling.test_te_cl(url)
        @reporter.add_result("HTTP Smuggling TE.CL", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = HTTPSmuggling.test_te_te(url)
        @reporter.add_result("HTTP Smuggling TE.TE", result)
        pause
      when 0 then return
      end
    end
  end

  def subdomain_takeover_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Check Subdomain")
      puts Colorize.yellow("  [2]  Scan Domain")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter subdomain: ")
        subdomain = gets.chomp
        result = SubdomainTakeover.check_subdomain(subdomain)
        @reporter.add_result("Subdomain Takeover", result)
        pause
      when 2
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        results = SubdomainTakeover.scan_domain(domain)
        puts Colorize.green("Found #{results.length} subdomains")
        @reporter.add_result("Subdomain Scan", results)
        pause
      when 0 then return
      end
    end
  end

  def dns_rebinding_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test DNS Rebinding")
      puts Colorize.yellow("  [2]  Generate Payload")
      puts Colorize.yellow("  [3]  Test TTL")
      puts Colorize.yellow("  [4]  Test Cache Poisoning")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target domain: ")
        target = gets.chomp
        print Colorize.cyan("Enter attacker domain: ")
        attacker = gets.chomp
        result = DNSRebinding.test_dns_rebinding(target, attacker)
        @reporter.add_result("DNS Rebinding", result)
        pause
      when 2
        print Colorize.cyan("Enter target IP: ")
        target_ip = gets.chomp
        print Colorize.cyan("Enter attacker domain: ")
        attacker = gets.chomp
        result = DNSRebinding.generate_payload(target_ip, attacker)
        @reporter.add_result("DNS Rebinding Payload", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        result = DNSRebinding.test_ttl_manipulation(domain)
        @reporter.add_result("TTL Test", result)
        pause
      when 4
        print Colorize.cyan("Enter target domain: ")
        domain = gets.chomp
        result = DNSRebinding.test_browser_cache_poisoning(domain)
        @reporter.add_result("Cache Poisoning", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def prototype_pollution_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test URL Prototype Pollution")
      puts Colorize.yellow("  [2]  Test JSON Prototype Pollution")
      puts Colorize.yellow("  [3]  Test DOM XSS via Prototype")
      puts Colorize.yellow("  [4]  Test RCE via Prototype")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'input'): ")
        param = gets.chomp
        param = 'input' if param.empty?
        result = PrototypePollution.test_url_prototype_pollution(url, param)
        @reporter.add_result("URL Prototype Pollution", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = PrototypePollution.test_json_prototype_pollution(url, param)
        @reporter.add_result("JSON Prototype Pollution", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'input'): ")
        param = gets.chomp
        param = 'input' if param.empty?
        result = PrototypePollution.test_dom_xss_via_prototype(url, param)
        @reporter.add_result("DOM XSS via Prototype", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'input'): ")
        param = gets.chomp
        param = 'input' if param.empty?
        result = PrototypePollution.test_rce_via_prototype(url, param)
        @reporter.add_result("RCE via Prototype", result)
        pause
      when 0 then return
      end
    end
  end

  def authentication_bypass_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test SQL Injection Auth")
      puts Colorize.yellow("  [2]  Test Default Credentials")
      puts Colorize.yellow("  [3]  Test Session Fixation")
      puts Colorize.yellow("  [4]  Test Weak Password Policy")
      puts Colorize.yellow("  [5]  Test Brute Force Protection")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter login URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter username parameter (default 'username'): ")
        user_param = gets.chomp
        user_param = 'username' if user_param.empty?
        print Colorize.cyan("Enter password parameter (default 'password'): ")
        pass_param = gets.chomp
        pass_param = 'password' if pass_param.empty?
        result = AuthenticationBypass.test_sql_injection_auth(url, user_param, pass_param)
        @reporter.add_result("SQL Injection Auth", result)
        pause
      when 2
        print Colorize.cyan("Enter login URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter service (ssh/ftp/mysql/postgresql/rdp/web): ")
        service = gets.chomp
        service = nil if service.empty?
        result = AuthenticationBypass.test_default_credentials(url, service)
        @reporter.add_result("Default Credentials", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = AuthenticationBypass.test_session_fixation(url)
        @reporter.add_result("Session Fixation", result)
        pause
      when 4
        print Colorize.cyan("Enter registration URL: ")
        url = gets.chomp
        result = AuthenticationBypass.test_weak_password_policy(url)
        @reporter.add_result("Weak Password Policy", result)
        pause
      when 5
        print Colorize.cyan("Enter login URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter username (default 'admin'): ")
        username = gets.chomp
        username = 'admin' if username.empty?
        result = AuthenticationBypass.test_brute_force_protection(url, username)
        @reporter.add_result("Brute Force Protection", result)
        pause
      when 0 then return
      end
    end
  end

  def idor_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Sequential IDs")
      puts Colorize.yellow("  [2]  Test User ID Manipulation")
      puts Colorize.yellow("  [3]  Test Object Reference")
      puts Colorize.yellow("  [4]  Test HTTP Method Override")
      puts Colorize.yellow("  [5]  Test Parameter Pollution")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter ID parameter (default 'id'): ")
        param = gets.chomp
        param = 'id' if param.empty?
        print Colorize.cyan("Start ID (default 1): ")
        start = gets.chomp.to_i
        start = 1 if start == 0
        print Colorize.cyan("End ID (default 100): ")
        end_id = gets.chomp.to_i
        end_id = 100 if end_id == 0
        result = IDOR.test_sequential_ids(url, param, start, end_id)
        @reporter.add_result("Sequential IDs", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter user ID parameter (default 'user_id'): ")
        param = gets.chomp
        param = 'user_id' if param.empty?
        print Colorize.cyan("Enter target ID (optional): ")
        target = gets.chomp
        target = target.empty? ? nil : target.to_i
        result = IDOR.test_user_id_manipulation(url, param, target)
        @reporter.add_result("User ID Manipulation", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter object parameter (default 'object_id'): ")
        param = gets.chomp
        param = 'object_id' if param.empty?
        result = IDOR.test_object_reference(url, param)
        @reporter.add_result("Object Reference", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter ID parameter (default 'id'): ")
        param = gets.chomp
        param = 'id' if param.empty?
        result = IDOR.test_http_method_override(url, param)
        @reporter.add_result("HTTP Method Override", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter ID parameter (default 'id'): ")
        param = gets.chomp
        param = 'id' if param.empty?
        result = IDOR.test_parameter_pollution(url, param)
        @reporter.add_result("Parameter Pollution", result)
        pause
      when 0 then return
      end
    end
  end

  def csrf_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test CSRF Protection")
      puts Colorize.yellow("  [2]  Generate CSRF PoC")
      puts Colorize.yellow("  [3]  Test SameSite Cookie")
      puts Colorize.yellow("  [4]  Test Referer Validation")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter method (GET/POST/PUT/DELETE, default POST): ")
        method = gets.chomp.downcase.to_sym
        method = :post if method.empty?
        result = CSRF.test_csrf_protection(url, method)
        @reporter.add_result("CSRF Protection", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter action path: ")
        action = gets.chomp
        print Colorize.cyan("Enter parameters (key=value, comma-separated): ")
        params_str = gets.chomp
        params = {}
        params_str.split(',').each do |pair|
          key, value = pair.split('=')
          params[key.strip] = value.strip if key && value
        end
        result = CSRF.generate_csrf_poc(url, action, params)
        @reporter.add_result("CSRF PoC", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CSRF.test_same_site_cookie(url)
        @reporter.add_result("SameSite Cookie", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = CSRF.test_referer_validation(url)
        @reporter.add_result("Referer Validation", result)
        pause
      when 0 then return
      end
    end
  end

  def open_redirect_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Open Redirect")
      puts Colorize.yellow("  [2]  Test Header-based Redirect")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (optional, will test all if empty): ")
        param = gets.chomp
        param = nil if param.empty?
        result = OpenRedirect.test_open_redirect(url, param)
        @reporter.add_result("Open Redirect", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = OpenRedirect.test_header_based_redirect(url)
        @reporter.add_result("Header-based Redirect", result)
        pause
      when 0 then return
      end
    end
  end

  def phishing_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Phishing Page")
      puts Colorize.yellow("  [2]  Clone Target Page")
      puts Colorize.yellow("  [3]  Generate Short URL")
      puts Colorize.yellow("  [4]  Generate QR Code")
      puts Colorize.yellow("  [5]  Generate Email Template")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target URL: ")
        target = gets.chomp
        print Colorize.cyan("Enter phishing URL: ")
        phishing = gets.chomp
        print Colorize.cyan("Enter template (login/bank/email, default login): ")
        template = gets.chomp
        template = 'login' if template.empty?
        result = Phishing.generate_phishing_page(target, phishing, template)
        @reporter.add_result("Phishing Page", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target URL to clone: ")
        url = gets.chomp
        result = Phishing.generate_clone_page(url)
        @reporter.add_result("Cloned Page", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter long URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter service (bitly/tinyurl/isgd): ")
        service = gets.chomp
        service = 'bitly' if service.empty?
        result = Phishing.generate_short_url(url, service)
        @reporter.add_result("Short URL", result)
        pause
      when 4
        print Colorize.cyan("Enter URL for QR code: ")
        url = gets.chomp
        result = Phishing.generate_qr_code(url)
        @reporter.add_result("QR Code", { file: result })
        pause
      when 5
        print Colorize.cyan("Enter target name: ")
        target = gets.chomp
        print Colorize.cyan("Enter sender name: ")
        sender = gets.chomp
        print Colorize.cyan("Enter subject: ")
        subject = gets.chomp
        print Colorize.cyan("Enter body: ")
        body = gets.chomp
        print Colorize.cyan("Enter phishing URL: ")
        phishing = gets.chomp
        result = Phishing.generate_email_template(target, sender, subject, body, phishing)
        @reporter.add_result("Email Template", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def social_engineering_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Credential Harvester")
      puts Colorize.yellow("  [2]  Generate Phone Spoofer")
      puts Colorize.yellow("  [3]  Generate SMS Phishing")
      puts Colorize.yellow("  [4]  Generate Pretext Scenario")
      puts Colorize.yellow("  [5]  Generate Attachment Payload")
      puts Colorize.yellow("  [6]  Generate Watering Hole")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target service: ")
        service = gets.chomp
        print Colorize.cyan("Enter callback URL: ")
        callback = gets.chomp
        result = SocialEngineering.generate_credential_harvester(service, callback)
        @reporter.add_result("Credential Harvester", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target number: ")
        target = gets.chomp
        print Colorize.cyan("Enter caller ID: ")
        caller_id = gets.chomp
        result = SocialEngineering.generate_phone_number_spoofer(target, caller_id)
        @reporter.add_result("Phone Spoofer", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter target number: ")
        target = gets.chomp
        print Colorize.cyan("Enter message: ")
        message = gets.chomp
        print Colorize.cyan("Enter malicious link: ")
        link = gets.chomp
        result = SocialEngineering.generate_sms_phishing(target, message, link)
        @reporter.add_result("SMS Phishing", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter scenario (tech_support/bank_security/it_department): ")
        scenario = gets.chomp
        scenario = 'tech_support' if scenario.empty?
        print Colorize.cyan("Enter caller name: ")
        caller = gets.chomp
        print Colorize.cyan("Enter bank name (if applicable): ")
        bank = gets.chomp
        info = { caller_name: caller, bank_name: bank }
        result = SocialEngineering.generate_pretext_scenario(scenario, info)
        @reporter.add_result("Pretext Scenario", { file: result })
        pause
      when 5
        print Colorize.cyan("Enter filename: ")
        filename = gets.chomp
        print Colorize.cyan("Enter type (exe/pdf/doc/zip): ")
        type = gets.chomp
        type = 'exe' if type.empty?
        result = SocialEngineering.generate_attachment_payload(filename, type)
        @reporter.add_result("Attachment Payload", { file: result })
        pause
      when 6
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter malicious script: ")
        script = gets.chomp
        result = SocialEngineering.generate_watering_hole(url, script)
        @reporter.add_result("Watering Hole", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def email_spoofing_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Spoofed Email")
      puts Colorize.yellow("  [2]  Test SPF Record")
      puts Colorize.yellow("  [3]  Test DKIM Record")
      puts Colorize.yellow("  [4]  Test DMARC Record")
      puts Colorize.yellow("  [5]  Generate SMTP Relay Test")
      puts Colorize.yellow("  [6]  Generate Spear Phishing Email")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter from email: ")
        from = gets.chomp
        print Colorize.cyan("Enter to email: ")
        to = gets.chomp
        print Colorize.cyan("Enter subject: ")
        subject = gets.chomp
        print Colorize.cyan("Enter body: ")
        body = gets.chomp
        print Colorize.cyan("Enter reply-to (optional): ")
        reply = gets.chomp
        reply = nil if reply.empty?
        result = EmailSpoofing.generate_spoofed_email(from, to, subject, body, reply)
        @reporter.add_result("Spoofed Email", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        result = EmailSpoofing.test_spf_record(domain)
        @reporter.add_result("SPF Test", result)
        pause
      when 3
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        result = EmailSpoofing.test_dkim_record(domain)
        @reporter.add_result("DKIM Test", result)
        pause
      when 4
        print Colorize.cyan("Enter domain: ")
        domain = gets.chomp
        result = EmailSpoofing.test_dmarc_record(domain)
        @reporter.add_result("DMARC Test", result)
        pause
      when 5
        print Colorize.cyan("Enter target domain: ")
        domain = gets.chomp
        print Colorize.cyan("Enter SMTP server: ")
        smtp = gets.chomp
        result = EmailSpoofing.generate_smtp_relay_test(domain, smtp)
        @reporter.add_result("SMTP Relay Test", { file: result })
        pause
      when 6
        print Colorize.cyan("Enter target name: ")
        name = gets.chomp
        print Colorize.cyan("Enter target email: ")
        email = gets.chomp
        print Colorize.cyan("Enter pretext: ")
        pretext = gets.chomp
        print Colorize.cyan("Enter malicious link: ")
        link = gets.chomp
        result = EmailSpoofing.generate_spear_phishing_email(name, email, pretext, link)
        @reporter.add_result("Spear Phishing", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def malware_generator_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate PowerShell Dropper")
      puts Colorize.yellow("  [2]  Generate VBS Dropper")
      puts Colorize.yellow("  [3]  Generate Batch Dropper")
      puts Colorize.yellow("  [4]  Generate Macro Payload")
      puts Colorize.yellow("  [5]  Generate HTA Payload")
      puts Colorize.yellow("  [6]  Generate LNK Shortcut")
      puts Colorize.yellow("  [7]  Generate Obfuscated Payload")
      puts Colorize.yellow("  [8]  Generate Persistence Script")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter payload URL: ")
        url = gets.chomp
        result = MalwareGenerator.generate_powershell_dropper(url)
        @reporter.add_result("PowerShell Dropper", result)
        pause
      when 2
        print Colorize.cyan("Enter payload URL: ")
        url = gets.chomp
        result = MalwareGenerator.generate_vbs_dropper(url)
        @reporter.add_result("VBS Dropper", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter payload URL: ")
        url = gets.chomp
        result = MalwareGenerator.generate_batch_dropper(url)
        @reporter.add_result("Batch Dropper", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter payload URL: ")
        url = gets.chomp
        result = MalwareGenerator.generate_macro_payload(url)
        @reporter.add_result("Macro Payload", { file: result })
        pause
      when 5
        print Colorize.cyan("Enter payload URL: ")
        url = gets.chomp
        result = MalwareGenerator.generate_hta_payload(url)
        @reporter.add_result("HTA Payload", { file: result })
        pause
      when 6
        print Colorize.cyan("Enter target path: ")
        path = gets.chomp
        print Colorize.cyan("Enter icon path (optional): ")
        icon = gets.chomp
        icon = nil if icon.empty?
        result = MalwareGenerator.generate_lnk_shortcut(path, icon)
        @reporter.add_result("LNK Shortcut", { file: result })
        pause
      when 7
        print Colorize.cyan("Enter payload: ")
        payload = gets.chomp
        print Colorize.cyan("Enter method (base64/hex/rot13/xor): ")
        method = gets.chomp
        method = 'base64' if method.empty?
        result = MalwareGenerator.generate_obfuscated_payload(payload, method)
        puts Colorize.green("Obfuscated: #{result}")
        @reporter.add_result("Obfuscated Payload", { obfuscated: result })
        pause
      when 8
        print Colorize.cyan("Enter method (registry/scheduled_task/startup_folder): ")
        method = gets.chomp
        method = 'registry' if method.empty?
        result = MalwareGenerator.generate_persistence_script(method)
        @reporter.add_result("Persistence Script", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def credential_harvesting_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Setup Harvester Server")
      puts Colorize.yellow("  [2]  Generate Keylogger")
      puts Colorize.yellow("  [3]  Generate Form Grabber")
      puts Colorize.yellow("  [4]  Generate Cookie Stealer")
      puts Colorize.yellow("  [5]  Generate Session Hijacker")
      puts Colorize.yellow("  [6]  Generate Credential Dumper")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter port (default 8080): ")
        port = gets.chomp.to_i
        port = 8080 if port == 0
        print Colorize.cyan("Enter log file (optional): ")
        log = gets.chomp
        log = nil if log.empty?
        result = CredentialHarvesting.setup_harvester_server(port, log)
        @reporter.add_result("Harvester Server", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter output URL: ")
        url = gets.chomp
        result = CredentialHarvesting.generate_keylogger_javascript(url)
        @reporter.add_result("Keylogger", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter output URL: ")
        url = gets.chomp
        result = CredentialHarvesting.generate_form_grabbing_javascript(url)
        @reporter.add_result("Form Grabber", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter output URL: ")
        url = gets.chomp
        result = CredentialHarvesting.generate_cookie_stealer_javascript(url)
        @reporter.add_result("Cookie Stealer", { file: result })
        pause
      when 5
        print Colorize.cyan("Enter target URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter session parameter (default 'session_id'): ")
        param = gets.chomp
        param = 'session_id' if param.empty?
        result = CredentialHarvesting.generate_session_hijacking_script(url, param)
        @reporter.add_result("Session Hijacker", { file: result })
        pause
      when 6
        print Colorize.cyan("Enter target service (browser/password_manager): ")
        service = gets.chomp
        service = 'browser' if service.empty?
        result = CredentialHarvesting.generate_credential_dumper(service)
        @reporter.add_result("Credential Dumper", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def clickjacking_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Clickjacking Protection")
      puts Colorize.yellow("  [2]  Generate Clickjacking PoC")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = Clickjacking.test_clickjacking_protection(url)
        @reporter.add_result("Clickjacking Test", result)
        pause
      when 2
        print Colorize.cyan("Enter target URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter overlay text (optional): ")
        text = gets.chomp
        text = "Click here" if text.empty?
        result = Clickjacking.generate_clickjacking_poc(url, text)
        @reporter.add_result("Clickjacking PoC", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def mass_assignment_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Mass Assignment")
      puts Colorize.yellow("  [2]  Test JSON Mass Assignment")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter method (POST/PUT/PATCH, default POST): ")
        method = gets.chomp.downcase.to_sym
        method = :post if method.empty?
        result = MassAssignment.test_mass_assignment(url, method)
        @reporter.add_result("Mass Assignment", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = MassAssignment.test_json_mass_assignment(url)
        @reporter.add_result("JSON Mass Assignment", result)
        pause
      when 0 then return
      end
    end
  end

  def timing_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Timing Attack")
      puts Colorize.yellow("  [2]  Test Username Enumeration")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name: ")
        param = gets.chomp
        print Colorize.cyan("Enter correct value: ")
        correct = gets.chomp
        print Colorize.cyan("Enter wrong value: ")
        wrong = gets.chomp
        print Colorize.cyan("Enter iterations (default 100): ")
        iter = gets.chomp.to_i
        iter = 100 if iter == 0
        result = TimingAttacks.test_timing_attack(url, param, correct, wrong, iter)
        @reporter.add_result("Timing Attack", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter usernames (comma-separated): ")
        usernames = gets.chomp.split(',').map(&:strip)
        result = TimingAttacks.test_username_enumeration(url, usernames)
        @reporter.add_result("Username Enumeration", result)
        pause
      when 0 then return
      end
    end
  end

  def padding_oracle_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Padding Oracle")
      puts Colorize.yellow("  [2]  Test CBC Padding")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = PaddingOracle.test_padding_oracle(url, param)
        @reporter.add_result("Padding Oracle", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'ciphertext'): ")
        param = gets.chomp
        param = 'ciphertext' if param.empty?
        result = PaddingOracle.test_cbc_padding(url, param)
        @reporter.add_result("CBC Padding", result)
        pause
      when 0 then return
      end
    end
  end

  def crlf_injection_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test CRLF Injection")
      puts Colorize.yellow("  [2]  Test Header Injection")
      puts Colorize.yellow("  [3]  Test Log Poisoning")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'input'): ")
        param = gets.chomp
        param = 'input' if param.empty?
        result = CRLFInjection.test_crlf_injection(url, param)
        @reporter.add_result("CRLF Injection", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter header name: ")
        header = gets.chomp
        print Colorize.cyan("Enter header value: ")
        value = gets.chomp
        result = CRLFInjection.test_header_injection(url, header, value)
        @reporter.add_result("Header Injection", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'user'): ")
        param = gets.chomp
        param = 'user' if param.empty?
        result = CRLFInjection.test_log_poisoning(url, param)
        @reporter.add_result("Log Poisoning", result)
        pause
      when 0 then return
      end
    end
  end

  def insecure_random_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Weak Random")
      puts Colorize.yellow("  [2]  Test Session ID Entropy")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'token'): ")
        param = gets.chomp
        param = 'token' if param.empty?
        result = InsecureRandom.test_weak_random(url, param)
        @reporter.add_result("Weak Random", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = InsecureRandom.test_session_id_entropy(url)
        @reporter.add_result("Session ID Entropy", result)
        pause
      when 0 then return
      end
    end
  end

  def insecure_deserialization_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Java Deserialization")
      puts Colorize.yellow("  [2]  Test PHP Deserialization")
      puts Colorize.yellow("  [3]  Test Python Pickle")
      puts Colorize.yellow("  [4]  Test Ruby Marshal")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = InsecureDeserialization.test_java_deserialization(url, param)
        @reporter.add_result("Java Deserialization", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = InsecureDeserialization.test_php_deserialization(url, param)
        @reporter.add_result("PHP Deserialization", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = InsecureDeserialization.test_python_pickle(url, param)
        @reporter.add_result("Python Pickle", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'data'): ")
        param = gets.chomp
        param = 'data' if param.empty?
        result = InsecureDeserialization.test_ruby_marshal(url, param)
        @reporter.add_result("Ruby Marshal", result)
        pause
      when 0 then return
      end
    end
  end

  def exploit_chains_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Full Exploit Chain")
      puts Colorize.yellow("  [2]  Generate Privilege Escalation")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target URL: ")
        target = gets.chomp
        print Colorize.cyan("Enter callback URL: ")
        callback = gets.chomp
        result = ExploitChains.generate_full_chain(target, callback)
        @reporter.add_result("Exploit Chain", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target URL: ")
        target = gets.chomp
        result = ExploitChains.generate_privilege_escalation(target)
        @reporter.add_result("Privilege Escalation", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def lateral_movement_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Scan Internal Network")
      puts Colorize.yellow("  [2]  Bruteforce SSH")
      puts Colorize.yellow("  [3]  Test SMB Shares")
      puts Colorize.yellow("  [4]  Test WinRM")
      puts Colorize.yellow("  [5]  Test RDP")
      puts Colorize.yellow("  [6]  Execute Remote Command")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter base IP (e.g., 192.168.1): ")
        base = gets.chomp
        print Colorize.cyan("Enter ports (comma-separated, default 22,80,443,3389): ")
        ports_str = gets.chomp
        ports = ports_str.empty? ? [22, 80, 443, 3389] : ports_str.split(',').map(&:to_i)
        result = LateralMovement.scan_internal_network(base, ports)
        @reporter.add_result("Internal Network Scan", result)
        pause
      when 2
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 22): ")
        port = gets.chomp.to_i
        port = 22 if port == 0
        print Colorize.cyan("Enter usernames (comma-separated): ")
        users = gets.chomp.split(',').map(&:strip)
        print Colorize.cyan("Enter passwords (comma-separated): ")
        pass = gets.chomp.split(',').map(&:strip)
        result = LateralMovement.bruteforce_ssh(host, port, users, pass)
        @reporter.add_result("SSH Bruteforce", result)
        pause
      when 3
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter username: ")
        user = gets.chomp
        print Colorize.cyan("Enter password: ")
        pass = gets.chomp
        result = LateralMovement.test_smb_shares(host, user, pass)
        @reporter.add_result("SMB Shares", result)
        pause
      when 4
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter username: ")
        user = gets.chomp
        print Colorize.cyan("Enter password: ")
        pass = gets.chomp
        result = LateralMovement.test_winrm(host, user, pass)
        @reporter.add_result("WinRM", result)
        pause
      when 5
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter port (default 3389): ")
        port = gets.chomp.to_i
        port = 3389 if port == 0
        print Colorize.cyan("Enter username: ")
        user = gets.chomp
        print Colorize.cyan("Enter password: ")
        pass = gets.chomp
        result = LateralMovement.test_rdp(host, port, user, pass)
        @reporter.add_result("RDP", result)
        pause
      when 6
        print Colorize.cyan("Enter host: ")
        host = gets.chomp
        print Colorize.cyan("Enter username: ")
        user = gets.chomp
        print Colorize.cyan("Enter password: ")
        pass = gets.chomp
        print Colorize.cyan("Enter command: ")
        cmd = gets.chomp
        print Colorize.cyan("Enter method (ssh/winrm): ")
        method = gets.chomp
        method = 'ssh' if method.empty?
        result = LateralMovement.execute_remote_command(host, user, pass, cmd, method)
        @reporter.add_result("Remote Command", result)
        pause
      when 0 then return
      end
    end
  end

  def persistence_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Windows Persistence")
      puts Colorize.yellow("  [2]  Generate Linux Persistence")
      puts Colorize.yellow("  [3]  Generate Web Shell Persistence")
      puts Colorize.yellow("  [4]  Generate Backdoor Account")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = Persistence.generate_windows_persistence
        @reporter.add_result("Windows Persistence", { file: result })
        pause
      when 2
        result = Persistence.generate_linux_persistence
        @reporter.add_result("Linux Persistence", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter shell path: ")
        path = gets.chomp
        result = Persistence.generate_web_shell_persistence(url, path)
        @reporter.add_result("Web Persistence", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter username: ")
        user = gets.chomp
        print Colorize.cyan("Enter password: ")
        pass = gets.chomp
        result = Persistence.generate_backdoor_account(user, pass)
        @reporter.add_result("Backdoor Account", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def data_exfiltration_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Exfiltrate via DNS")
      puts Colorize.yellow("  [2]  Exfiltrate via HTTP")
      puts Colorize.yellow("  [3]  Exfiltrate via ICMP")
      puts Colorize.yellow("  [4]  Generate Exfiltration Server")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target data: ")
        data = gets.chomp
        print Colorize.cyan("Enter DNS server: ")
        dns = gets.chomp
        result = DataExfiltration.exfiltrate_via_dns(data, dns)
        @reporter.add_result("DNS Exfiltration", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target data: ")
        data = gets.chomp
        print Colorize.cyan("Enter callback URL: ")
        url = gets.chomp
        result = DataExfiltration.exfiltrate_via_http(data, url)
        @reporter.add_result("HTTP Exfiltration", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter target data: ")
        data = gets.chomp
        print Colorize.cyan("Enter target IP: ")
        ip = gets.chomp
        result = DataExfiltration.exfiltrate_via_icmp(data, ip)
        @reporter.add_result("ICMP Exfiltration", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter port (default 8080): ")
        port = gets.chomp.to_i
        port = 8080 if port == 0
        result = DataExfiltration.generate_exfiltration_server(port)
        @reporter.add_result("Exfiltration Server", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def post_exploitation_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Recon Script")
      puts Colorize.yellow("  [2]  Generate Credential Harvester")
      puts Colorize.yellow("  [3]  Generate Network Sniffer")
      puts Colorize.yellow("  [4]  Generate Keylogger")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = PostExploitation.generate_recon_script
        @reporter.add_result("Recon Script", { file: result })
        pause
      when 2
        result = PostExploitation.generate_credential_harvester
        @reporter.add_result("Credential Harvester", { file: result })
        pause
      when 3
        result = PostExploitation.generate_network_sniffer
        @reporter.add_result("Network Sniffer", { file: result })
        pause
      when 4
        result = PostExploitation.generate_keylogger
        @reporter.add_result("Keylogger", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def evasion_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Obfuscate Payload")
      puts Colorize.yellow("  [2]  Generate Polymorphic Payload")
      puts Colorize.yellow("  [3]  Generate WAF Bypass Payloads")
      puts Colorize.yellow("  [4]  Generate IPS Evasion")
      puts Colorize.yellow("  [5]  Generate AV Evasion")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter payload: ")
        payload = gets.chomp
        print Colorize.cyan("Enter method (base64/hex/unicode/rot13/xor/double_encode): ")
        method = gets.chomp
        method = 'base64' if method.empty?
        result = Evasion.obfuscate_payload(payload, method)
        puts Colorize.green("Obfuscated: #{result}")
        @reporter.add_result("Obfuscated Payload", { obfuscated: result })
        pause
      when 2
        print Colorize.cyan("Enter base payload: ")
        payload = gets.chomp
        result = Evasion.generate_polymorphic_payload(payload)
        result.each_with_index { |v, i| puts "#{i+1}. #{v}" }
        @reporter.add_result("Polymorphic Payloads", result)
        pause
      when 3
        print Colorize.cyan("Enter original payload: ")
        payload = gets.chomp
        result = Evasion.generate_waf_bypass_payloads(payload)
        result.each_with_index { |v, i| puts "#{i+1}. #{v}" }
        @reporter.add_result("WAF Bypass Payloads", result)
        pause
      when 4
        print Colorize.cyan("Enter original payload: ")
        payload = gets.chomp
        result = Evasion.generate_ips_evasion(payload)
        result.each_with_index { |v, i| puts "#{i+1}. #{v}" }
        @reporter.add_result("IPS Evasion", result)
        pause
      when 5
        print Colorize.cyan("Enter payload: ")
        payload = gets.chomp
        result = Evasion.generate_av_evasion(payload)
        @reporter.add_result("AV Evasion", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def zero_day_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Log4j")
      puts Colorize.yellow("  [2]  Test Spring4Shell")
      puts Colorize.yellow("  [3]  Test Apache Struts")
      puts Colorize.yellow("  [4]  Test Apache Solr")
      puts Colorize.yellow("  [5]  Test Ghostcat")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter parameter name (default 'input'): ")
        param = gets.chomp
        param = 'input' if param.empty?
        result = ZeroDay.test_log4j(url, param)
        @reporter.add_result("Log4j Test", result)
        pause
      when 2
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = ZeroDay.test_spring4shell(url)
        @reporter.add_result("Spring4Shell Test", result)
        pause
      when 3
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = ZeroDay.test_apache_struts(url)
        @reporter.add_result("Apache Struts Test", result)
        pause
      when 4
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = ZeroDay.test_apache_solr(url)
        @reporter.add_result("Apache Solr Test", result)
        pause
      when 5
        print Colorize.cyan("Enter URL: ")
        url = gets.chomp
        result = ZeroDay.test_ghostcat(url)
        @reporter.add_result("Ghostcat Test", result)
        pause
      when 0 then return
      end
    end
  end

  def c2_framework_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate C2 Server")
      puts Colorize.yellow("  [2]  Generate C2 Client")
      puts Colorize.yellow("  [3]  Generate HTTP C2 Server")
      puts Colorize.yellow("  [4]  Generate HTTP C2 Client")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter port (default 4444): ")
        port = gets.chomp.to_i
        port = 4444 if port == 0
        result = C2Framework.generate_c2_server(port)
        @reporter.add_result("C2 Server", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter server IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port (default 4444): ")
        port = gets.chomp.to_i
        port = 4444 if port == 0
        result = C2Framework.generate_c2_client(ip, port)
        @reporter.add_result("C2 Client", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter port (default 8080): ")
        port = gets.chomp.to_i
        port = 8080 if port == 0
        result = C2Framework.generate_http_c2_server(port)
        @reporter.add_result("HTTP C2 Server", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter server URL: ")
        url = gets.chomp
        result = C2Framework.generate_http_c2_client(url)
        @reporter.add_result("HTTP C2 Client", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def ransomware_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Encryption Key")
      puts Colorize.yellow("  [2]  Generate Ransomware Script")
      puts Colorize.yellow("  [3]  Generate Ransom Note")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = Ransomware.generate_encryption_key
        @reporter.add_result("Encryption Key", result)
        pause
      when 2
        print Colorize.cyan("Enter target directory (default /tmp): ")
        dir = gets.chomp
        dir = '/tmp' if dir.empty?
        result = Ransomware.generate_ransomware_script(dir)
        @reporter.add_result("Ransomware Script", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter Bitcoin address: ")
        btc = gets.chomp
        print Colorize.cyan("Enter email: ")
        email = gets.chomp
        print Colorize.cyan("Enter amount (default 0.1): ")
        amount = gets.chomp
        amount = '0.1' if amount.empty?
        result = Ransomware.generate_ransom_note(btc, email, amount)
        @reporter.add_result("Ransom Note", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def botnet_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Botnet Server")
      puts Colorize.yellow("  [2]  Generate Botnet Client")
      puts Colorize.yellow("  [3]  Generate DDoS Script")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter port (default 5555): ")
        port = gets.chomp.to_i
        port = 5555 if port == 0
        result = Botnet.generate_botnet_server(port)
        @reporter.add_result("Botnet Server", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter server IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port (default 5555): ")
        port = gets.chomp.to_i
        port = 5555 if port == 0
        result = Botnet.generate_botnet_client(ip, port)
        @reporter.add_result("Botnet Client", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter target URL: ")
        url = gets.chomp
        print Colorize.cyan("Enter threads (default 100): ")
        threads = gets.chomp.to_i
        threads = 100 if threads == 0
        print Colorize.cyan("Enter duration in seconds (default 60): ")
        duration = gets.chomp.to_i
        duration = 60 if duration == 0
        result = Botnet.generate_ddos_script(url, threads, duration)
        @reporter.add_result("DDoS Script", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def crypto_mining_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Miner Script")
      puts Colorize.yellow("  [2]  Generate Browser Miner")
      puts Colorize.yellow("  [3]  Generate Persistence Miner")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter pool URL: ")
        pool = gets.chomp
        print Colorize.cyan("Enter wallet address: ")
        wallet = gets.chomp
        print Colorize.cyan("Enter worker name (optional): ")
        worker = gets.chomp
        worker = 'worker' if worker.empty?
        result = CryptoMining.generate_miner_script(pool, wallet, worker)
        @reporter.add_result("Miner Script", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter pool URL: ")
        pool = gets.chomp
        print Colorize.cyan("Enter wallet address: ")
        wallet = gets.chomp
        result = CryptoMining.generate_browser_miner(pool, wallet)
        @reporter.add_result("Browser Miner", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter pool URL: ")
        pool = gets.chomp
        print Colorize.cyan("Enter wallet address: ")
        wallet = gets.chomp
        result = CryptoMining.generate_persistence_miner(pool, wallet)
        @reporter.add_result("Persistence Miner", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def rootkit_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Linux Rootkit")
      puts Colorize.yellow("  [2]  Generate Windows Rootkit")
      puts Colorize.yellow("  [3]  Generate Process Hider")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = Rootkit.generate_linux_rootkit
        @reporter.add_result("Linux Rootkit", { file: result })
        pause
      when 2
        result = Rootkit.generate_windows_rootkit
        @reporter.add_result("Windows Rootkit", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter process name: ")
        process = gets.chomp
        result = Rootkit.generate_process_hider(process)
        @reporter.add_result("Process Hider", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def memory_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Buffer Overflow")
      puts Colorize.yellow("  [2]  Generate ROP Chain")
      puts Colorize.yellow("  [3]  Generate Heap Spray")
      puts Colorize.yellow("  [4]  Generate Format String")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter target binary: ")
        binary = gets.chomp
        print Colorize.cyan("Enter offset (default 100): ")
        offset = gets.chomp.to_i
        offset = 100 if offset == 0
        result = MemoryAttacks.generate_buffer_overflow_exploit(binary, offset)
        @reporter.add_result("Buffer Overflow", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target binary: ")
        binary = gets.chomp
        result = MemoryAttacks.generate_rop_chain(binary)
        @reporter.add_result("ROP Chain", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter heap size (default 0x1000000): ")
        size_str = gets.chomp
        size = size_str.empty? ? 0x1000000 : size_str.to_i(16)
        result = MemoryAttacks.generate_heap_spray(size)
        @reporter.add_result("Heap Spray", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter target binary: ")
        binary = gets.chomp
        result = MemoryAttacks.generate_format_string_exploit(binary)
        @reporter.add_result("Format String", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def wireless_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate WiFi Deauth")
      puts Colorize.yellow("  [2]  Generate WiFi Capture")
      puts Colorize.yellow("  [3]  Generate WPS Attack")
      puts Colorize.yellow("  [4]  Generate Evil Twin")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter interface: ")
        interface = gets.chomp
        print Colorize.cyan("Enter target MAC: ")
        mac = gets.chomp
        print Colorize.cyan("Enter duration (default 10): ")
        duration = gets.chomp.to_i
        duration = 10 if duration == 0
        result = WirelessAttacks.generate_wifi_deauth(interface, mac, duration)
        @reporter.add_result("WiFi Deauth", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter interface: ")
        interface = gets.chomp
        print Colorize.cyan("Enter output file (optional): ")
        output = gets.chomp
        output = nil if output.empty?
        result = WirelessAttacks.generate_wifi_capture(interface, output)
        @reporter.add_result("WiFi Capture", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter interface: ")
        interface = gets.chomp
        print Colorize.cyan("Enter BSSID: ")
        bssid = gets.chomp
        result = WirelessAttacks.generate_wps_attack(interface, bssid)
        @reporter.add_result("WPS Attack", { file: result })
        pause
      when 4
        print Colorize.cyan("Enter interface: ")
        interface = gets.chomp
        print Colorize.cyan("Enter SSID: ")
        ssid = gets.chomp
        result = WirelessAttacks.generate_evil_twin(interface, ssid)
        @reporter.add_result("Evil Twin", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def bluetooth_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Bluetooth Scan")
      puts Colorize.yellow("  [2]  Generate Bluetooth Spoof")
      puts Colorize.yellow("  [3]  Generate Bluebug Attack")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = BluetoothAttacks.generate_bluetooth_scan
        @reporter.add_result("Bluetooth Scan", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter target MAC: ")
        target = gets.chomp
        print Colorize.cyan("Enter spoofed MAC: ")
        spoofed = gets.chomp
        result = BluetoothAttacks.generate_bluetooth_spoof(target, spoofed)
        @reporter.add_result("Bluetooth Spoof", { file: result })
        pause
      when 3
        print Colorize.cyan("Enter target MAC: ")
        mac = gets.chomp
        result = BluetoothAttacks.generate_bluebug_attack(mac)
        @reporter.add_result("Bluebug Attack", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def iot_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Scan IoT Devices")
      puts Colorize.yellow("  [2]  Test Default Credentials")
      puts Colorize.yellow("  [3]  Test MQTT Unauthorized")
      puts Colorize.yellow("  [4]  Test Telnet Access")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter network range (e.g., 192.168.1): ")
        range = gets.chomp
        result = IoTAttacks.scan_iot_devices(range)
        @reporter.add_result("IoT Scan", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port (default 80): ")
        port = gets.chomp.to_i
        port = 80 if port == 0
        result = IoTAttacks.test_default_credentials_iot(ip, port)
        @reporter.add_result("IoT Default Credentials", result)
        pause
      when 3
        print Colorize.cyan("Enter IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port (default 1883): ")
        port = gets.chomp.to_i
        port = 1883 if port == 0
        result = IoTAttacks.test_mqtt_unauthorized(ip, port)
        @reporter.add_result("MQTT Unauthorized", result)
        pause
      when 4
        print Colorize.cyan("Enter IP: ")
        ip = gets.chomp
        print Colorize.cyan("Enter port (default 23): ")
        port = gets.chomp.to_i
        port = 23 if port == 0
        result = IoTAttacks.test_telnet_access(ip, port)
        @reporter.add_result("Telnet Access", result)
        pause
      when 0 then return
      end
    end
  end

  def mobile_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Generate Android APK Backdoor")
      puts Colorize.yellow("  [2]  Generate iOS IPA Backdoor")
      puts Colorize.yellow("  [3]  Generate SMS Interceptor")
      puts Colorize.yellow("  [4]  Generate Location Tracker")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter package name: ")
        package = gets.chomp
        print Colorize.cyan("Enter callback URL: ")
        callback = gets.chomp
        result = MobileAttacks.generate_android_apk_backdoor(package, callback)
        @reporter.add_result("Android Backdoor", { file: result })
        pause
      when 2
        print Colorize.cyan("Enter callback URL: ")
        callback = gets.chomp
        result = MobileAttacks.generate_ios_ipa_backdoor(callback)
        @reporter.add_result("iOS Backdoor", { file: result })
        pause
      when 3
        result = MobileAttacks.generate_sms_interceptor
        @reporter.add_result("SMS Interceptor", { file: result })
        pause
      when 4
        result = MobileAttacks.generate_location_tracker
        @reporter.add_result("Location Tracker", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def cloud_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test AWS S3 Bucket")
      puts Colorize.yellow("  [2]  Test Azure Blob Storage")
      puts Colorize.yellow("  [3]  Test GCP Bucket")
      puts Colorize.yellow("  [4]  Test AWS Metadata Service")
      puts Colorize.yellow("  [5]  Test Azure Metadata Service")
      puts Colorize.yellow("  [6]  Test GCP Metadata Service")
      puts Colorize.yellow("  [7]  Generate Cloud Credential Harvester")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        print Colorize.cyan("Enter bucket name: ")
        bucket = gets.chomp
        result = CloudAttacks.test_aws_s3_bucket(bucket)
        @reporter.add_result("AWS S3 Bucket", result)
        pause
      when 2
        print Colorize.cyan("Enter account name: ")
        account = gets.chomp
        print Colorize.cyan("Enter container name: ")
        container = gets.chomp
        result = CloudAttacks.test_azure_blob_storage(account, container)
        @reporter.add_result("Azure Blob Storage", result)
        pause
      when 3
        print Colorize.cyan("Enter bucket name: ")
        bucket = gets.chomp
        result = CloudAttacks.test_gcp_bucket(bucket)
        @reporter.add_result("GCP Bucket", result)
        pause
      when 4
        result = CloudAttacks.test_aws_metadata_service
        @reporter.add_result("AWS Metadata", result)
        pause
      when 5
        result = CloudAttacks.test_azure_metadata_service
        @reporter.add_result("Azure Metadata", result)
        pause
      when 6
        result = CloudAttacks.test_gcp_metadata_service
        @reporter.add_result("GCP Metadata", result)
        pause
      when 7
        result = CloudAttacks.generate_cloud_credential_harvester
        @reporter.add_result("Cloud Harvester", { file: result })
        pause
      when 0 then return
      end
    end
  end

  def container_attacks_menu
    loop do
      system("clear") || system("cls")
      banner
      puts Colorize.yellow("  [1]  Test Docker Escape")
      puts Colorize.yellow("  [2]  Test Kubernetes Escape")
      puts Colorize.yellow("  [3]  Generate Container Breakout")
      puts Colorize.yellow("  [4]  Test Docker Socket Access")
      puts Colorize.yellow("  [0]  Back")
      print Colorize.bold(Colorize.green("> "))
      choice = gets.chomp.to_i
      case choice
      when 1
        result = ContainerAttacks.test_docker_escape
        @reporter.add_result("Docker Escape", { file: result })
        pause
      when 2
        result = ContainerAttacks.test_kubernetes_escape
        @reporter.add_result("Kubernetes Escape", { file: result })
        pause
      when 3
        result = ContainerAttacks.generate_container_breakout
        @reporter.add_result("Container Breakout", { file: result })
        pause
      when 4
        result = ContainerAttacks.test_docker_socket_access
        @reporter.add_result("Docker Socket", { file: result })
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

