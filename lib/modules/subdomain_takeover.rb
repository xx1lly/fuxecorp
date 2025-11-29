require 'resolv'
require 'net/http'
require 'uri'
require_relative '../utils/colorize'

class SubdomainTakeover
  SERVICES = {
    'github.io' => 'GitHub Pages',
    'herokuapp.com' => 'Heroku',
    'azurewebsites.net' => 'Azure',
    'cloudapp.net' => 'Azure',
    's3.amazonaws.com' => 'AWS S3',
    's3-website-us-east-1.amazonaws.com' => 'AWS S3',
    's3-website-us-west-1.amazonaws.com' => 'AWS S3',
    's3-website-us-west-2.amazonaws.com' => 'AWS S3',
    's3-website-eu-west-1.amazonaws.com' => 'AWS S3',
    's3-website-ap-southeast-1.amazonaws.com' => 'AWS S3',
    's3-website-ap-southeast-2.amazonaws.com' => 'AWS S3',
    's3-website-ap-northeast-1.amazonaws.com' => 'AWS S3',
    's3-website-sa-east-1.amazonaws.com' => 'AWS S3',
    'cloudfront.net' => 'AWS CloudFront',
    'fastly.com' => 'Fastly',
    'fastly.net' => 'Fastly',
    'readthedocs.io' => 'ReadTheDocs',
    'bitbucket.io' => 'Bitbucket',
    'tumblr.com' => 'Tumblr',
    'wordpress.com' => 'WordPress',
    'shopify.com' => 'Shopify',
    'help.shopify.com' => 'Shopify',
    'myshopify.com' => 'Shopify',
    'unbounce.com' => 'Unbounce',
    'pantheonsite.io' => 'Pantheon',
    'domains.tumblr.com' => 'Tumblr',
    'wpengine.com' => 'WP Engine',
    'desk.com' => 'Desk.com',
    'zendesk.com' => 'Zendesk',
    'uservoice.com' => 'UserVoice',
    'feedpress.me' => 'FeedPress',
    'ghost.io' => 'Ghost',
    'cargocollective.com' => 'Cargo Collective',
    'statuspage.io' => 'StatusPage',
    'surge.sh' => 'Surge.sh',
    'bitly.com' => 'Bitly',
    'smartling.com' => 'Smartling',
    'acquia.com' => 'Acquia',
    'acquia-test.co' => 'Acquia',
    'cargo.site' => 'Cargo',
    'hatenablog.com' => 'Hatena',
    'hatenablog.jp' => 'Hatena',
    'hatenadiary.com' => 'Hatena',
    'hatenadiary.jp' => 'Hatena',
    'hatenadiary.org' => 'Hatena',
    'hatenadiary.net' => 'Hatena',
    'hatenadiary.info' => 'Hatena',
    'hatenadiary.biz' => 'Hatena',
    'hatenadiary.us' => 'Hatena',
    'hatenadiary.com' => 'Hatena',
    'hatenadiary.jp' => 'Hatena',
    'hatenadiary.org' => 'Hatena',
    'hatenadiary.net' => 'Hatena',
    'hatenadiary.info' => 'Hatena',
    'hatenadiary.biz' => 'Hatena',
    'hatenadiary.us' => 'Hatena'
  }

  def self.check_subdomain(subdomain)
    begin
      resolver = Resolv::DNS.new
      cname = resolver.getresource(subdomain, Resolv::DNS::Resource::IN::CNAME)
      
      if cname
        target = cname.name.to_s
        service = identify_service(target)
        
        if service
          if is_vulnerable(target, service)
            puts Colorize.red("Vulnerable subdomain: #{subdomain} -> #{target} (#{service})")
            return { subdomain: subdomain, target: target, service: service, vulnerable: true }
          else
            puts Colorize.yellow("Subdomain found: #{subdomain} -> #{target} (#{service})")
            return { subdomain: subdomain, target: target, service: service, vulnerable: false }
          end
        end
      end
    rescue Resolv::ResolvError
    rescue => e
    end
    
    nil
  end

  def self.identify_service(domain)
    SERVICES.each do |pattern, service|
      if domain.include?(pattern)
        return service
      end
    end
    nil
  end

  def self.is_vulnerable(domain, service)
    begin
      uri = URI("http://#{domain}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = 5
      req = Net::HTTP::Get.new('/')
      res = http.request(req)
      
      case service
      when 'GitHub Pages'
        return res.body.include?('There isn\'t a GitHub Pages site here') || res.body.include?('404')
      when 'Heroku'
        return res.body.include?('No such app') || res.body.include?('herokucdn.com/error-pages/no-such-app.html')
      when 'AWS S3'
        return res.body.include?('NoSuchBucket') || res.body.include?('The specified bucket does not exist')
      when 'AWS CloudFront'
        return res.body.include?('ERROR: The request could not be satisfied')
      when 'Fastly'
        return res.body.include?('Fastly error: unknown domain')
      when 'ReadTheDocs'
        return res.body.include?('Read the Docs')
      when 'Bitbucket'
        return res.body.include?('Repository not found')
      when 'Tumblr'
        return res.body.include?('Whatever you were looking for doesn\'t currently exist at this address')
      when 'WordPress'
        return res.body.include?('Do you want to register')
      when 'Shopify'
        return res.body.include?('Sorry, this shop is currently unavailable')
      when 'Unbounce'
        return res.body.include?('The requested URL was not found on this server')
      when 'Pantheon'
        return res.body.include?('404 error unknown site')
      when 'WP Engine'
        return res.body.include?('The site you are looking for could not be found')
      when 'Zendesk'
        return res.body.include?('Help Center Closed')
      when 'UserVoice'
        return res.body.include?('This UserVoice instance does not exist')
      when 'FeedPress'
        return res.body.include?('The feed has not been found')
      when 'Ghost'
        return res.body.include?('The thing you were looking for is not found')
      when 'Cargo Collective'
        return res.body.include?('404 Not Found')
      when 'StatusPage'
        return res.body.include?('You are being redirected')
      when 'Surge.sh'
        return res.body.include?('project not found')
      when 'Bitly'
        return res.body.include?('bit.ly')
      when 'Smartling'
        return res.body.include?('Domain is not configured')
      when 'Acquia'
        return res.body.include?('The site you are looking for could not be found')
      end
    rescue => e
    end
    
    false
  end

  def self.scan_domain(domain)
    subdomains = []
    common_prefixes = %w[www mail ftp admin test dev staging prod api blog shop store support help docs wiki cdn static assets media img images js css files upload download backup db database config admin panel cpanel webmail smtp pop imap mx ns dns ns1 ns2 ns3 ns4 mail1 mail2 mail3 mail4 smtp1 smtp2 pop1 pop2 imap1 imap2]
    
    common_prefixes.each do |prefix|
      subdomain = "#{prefix}.#{domain}"
      result = check_subdomain(subdomain)
      subdomains << result if result
    end
    
    subdomains
  end
end

