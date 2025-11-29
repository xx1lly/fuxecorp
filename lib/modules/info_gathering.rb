require 'net/http'
require 'uri'
require 'json'
require 'resolv'
require_relative '../utils/network'
require_relative '../utils/colorize'

class InfoGathering
  def self.whois(domain)
    `whois #{domain}` rescue "Error"
  end

  def self.dns_lookup(domain)
    results = {}
    %w[A AAAA MX NS TXT CNAME].each do |type|
      begin
        result = Resolv::DNS.open do |dns|
          case type
          when 'A'
            dns.getresources(domain, Resolv::DNS::Resource::IN::A).map(&:address)
          when 'AAAA'
            dns.getresources(domain, Resolv::DNS::Resource::IN::AAAA).map(&:address)
          when 'MX'
            dns.getresources(domain, Resolv::DNS::Resource::IN::MX).map { |r| "#{r.preference} #{r.exchange}" }
          when 'NS'
            dns.getresources(domain, Resolv::DNS::Resource::IN::NS).map(&:name)
          when 'TXT'
            dns.getresources(domain, Resolv::DNS::Resource::IN::TXT).map(&:strings).flatten
          else []
          end
        end
        results[type] = result unless result.empty?
      rescue
      end
    end
    results
  end

  def self.reverse_dns(ip)
    Resolv.getname(ip) rescue nil
  end

  def self.subdomain_enumeration(domain, wordlist = nil)
    wordlist ||= %w[www mail ftp localhost test dev admin blog shop api m cdn static media img images js css assets files upload download secure vpn remote ssh telnet smtp pop imap webmail email mx ns dns www2 www3 admin2 test2 dev2 staging production prod beta alpha demo sandbox support help docs wiki forum community news store cart checkout account login signin signup register profile user users member members dashboard panel control cpanel whm phpmyadmin mysql sql db database backup backups old archive archives temp tmp cache log logs]
    
    found = []
    wordlist.each do |sub|
      begin
        hostname = "#{sub}.#{domain}"
        ip = Network.resolve_host(hostname)
        if ip
          puts Colorize.green("Found: #{hostname} -> #{ip}")
          found << { hostname: hostname, ip: ip }
        end
      rescue
      end
    end
    found
  end

  def self.ip_geolocation(ip)
    begin
      uri = URI("http://ip-api.com/json/#{ip}")
      response = Net::HTTP.get_response(uri)
      JSON.parse(response.body)
    rescue
      nil
    end
  end

  def self.banner_grab(host, port)
    Network.banner_grab(host, port)
  end

  def self.os_detection(ip)
    begin
      result = `ping -n 1 #{ip}` rescue `ping -c 1 #{ip}`
      ttl = result.match(/TTL=(\d+)/i)
      return nil unless ttl
      
      ttl_val = ttl[1].to_i
      case ttl_val
      when 0..64 then 'Linux/Unix'
      when 65..128 then 'Windows'
      else 'Unknown'
      end
    rescue
      nil
    end
  end
end

