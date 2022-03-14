#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'fileutils'
require 'open3'

class ServerAuditor
  def initialize
    @timestamp = Time.now.strftime("%Y%m%d_%H%M%S")
    @report_file = "security-assessment-#{@timestamp}.txt"
  end

  def run
    start_audit
    gather_system_info
    run_security_checks
    finalize_report
  end

  private

  def start_audit
    puts "System Security Assessment"
    puts "Initializing security evaluation at #{Time.now}\n"

    File.open(@report_file, 'w') do |f|
      f.puts "System Security Assessment Report"
      f.puts "Generated on #{Time.now}"
      f.puts "================================"
    end
  end

  def print_header(header)
    puts "\n#{header}"
    File.open(@report_file, 'a') do |f|
      f.puts "\n#{header}"
      f.puts "================================"
    end
  end

  def print_info(label, value)
    puts "#{label}: #{value}"
    File.open(@report_file, 'a') { |f| f.puts "#{label}: #{value}" }
  end

  def gather_system_info
    print_header("System Information")

    os_info = cmd_output("grep PRETTY_NAME /etc/os-release").split('"')[1] rescue "Unknown"
    kernel_version = cmd_output("uname -r").strip
    hostname = ENV['HOSTNAME'] || cmd_output("hostname").strip
    uptime = cmd_output("uptime -p").strip
    uptime_since = cmd_output("uptime -s").strip
    cpu_info = cmd_output("lscpu | grep 'Model name'").split(':')[1]&.strip || "Unknown"
    cpu_cores = cmd_output("nproc").strip
    total_mem = cmd_output("free -h | awk '/^Mem:/ {print $2}'").strip
    total_disk = cmd_output("df -h / | awk 'NR==2 {print $2}'").strip
    public_ip = get_public_ip
    load_average = cmd_output("uptime").split('load average:')[1]&.strip || "Unknown"

    print_info("Hostname", hostname)
    print_info("Operating System", os_info)
    print_info("Kernel Version", kernel_version)
    print_info("Uptime", "#{uptime} (since #{uptime_since})")
    print_info("CPU Model", cpu_info)
    print_info("CPU Cores", cpu_cores)
    print_info("Total Memory", total_mem)
    print_info("Total Disk Space", total_disk)
    print_info("Public IP", public_ip)
    print_info("Load Average", load_average)

    File.open(@report_file, 'a') { |f| f.puts "" }
  end

  def run_security_checks
    print_header("Security Assessment Results")

    uptime = cmd_output("uptime -p").strip
    uptime_since = cmd_output("uptime -s").strip

    File.open(@report_file, 'a') do |f|
      f.puts "\nSystem Uptime Information:"
      f.puts "Current uptime: #{uptime}"
      f.puts "System up since: #{uptime_since}"
      f.puts ""
    end
    puts "System Uptime: #{uptime} (since #{uptime_since})"

    check_restart_required
    check_ssh_configuration
    check_firewall_status
    check_unattended_upgrades
    check_intrusion_prevention
    check_failed_logins
    check_system_updates
    check_running_services
    check_port_security
    check_disk_usage
    check_memory_usage
    check_cpu_usage
    check_sudo_logging
    check_password_policy
    check_suid_files
  end

  def evaluate_status(test_name, status, message)
    puts "[#{status}] #{test_name} - #{message}"

    File.open(@report_file, 'a') do |f|
      f.puts "[#{status}] #{test_name} - #{message}"
      f.puts ""
    end
  end

  def check_restart_required
    if File.exist?("/var/run/reboot-required")
      evaluate_status("System Restart", "WARN", "System requires restart to complete pending updates")
    else
      evaluate_status("System Restart", "PASS", "No restart required")
    end
  end

  def check_ssh_configuration
    ssh_config_overrides = cmd_output("grep '^Include' /etc/ssh/sshd_config 2>/dev/null").split.last

    ssh_root = get_ssh_config_value("PermitRootLogin", ssh_config_overrides) || "prohibit-password"
    if ssh_root == "no"
      evaluate_status("SSH Root Login", "PASS", "Root access properly disabled in SSH configuration")
    else
      evaluate_status("SSH Root Login", "FAIL", "Root access currently enabled - significant security risk. Disable in /etc/ssh/sshd_config")
    end

    ssh_password = get_ssh_config_value("PasswordAuthentication", ssh_config_overrides) || "yes"
    if ssh_password == "no"
      evaluate_status("SSH Password Auth", "PASS", "Password authentication disabled, key-based authentication enforced")
    else
      evaluate_status("SSH Password Auth", "FAIL", "Password authentication enabled - recommend key-based authentication only")
    end

    unprivileged_port_start = cmd_output("sysctl -n net.ipv4.ip_unprivileged_port_start").strip.to_i
    ssh_port = (get_ssh_config_value("Port", ssh_config_overrides) || "22").to_i

    case
    when ssh_port == 22
      evaluate_status("SSH Port", "WARN", "Default port 22 in use - consider non-standard port for enhanced security")
    when ssh_port >= unprivileged_port_start
      evaluate_status("SSH Port", "FAIL", "Unprivileged port #{ssh_port} in use - use port below #{unprivileged_port_start} for better security")
    else
      evaluate_status("SSH Port", "PASS", "Non-default port #{ssh_port} configured - helps mitigate automated attacks")
    end
  end

  def get_ssh_config_value(key, overrides_file)
    if overrides_file && !overrides_file.empty? && File.directory?(File.dirname(overrides_file))
      result = cmd_output("grep '^#{key}' #{overrides_file} /etc/ssh/sshd_config 2>/dev/null | head -1").split.last
    else
      result = cmd_output("grep '^#{key}' /etc/ssh/sshd_config 2>/dev/null | head -1").split.last
    end
    result
  end

  def check_firewall_status
    if command_exists?("ufw")
      if cmd_output("ufw status").include?("active")
        evaluate_status("Firewall Status (UFW)", "PASS", "UFW firewall active and protecting system")
      else
        evaluate_status("Firewall Status (UFW)", "FAIL", "UFW firewall inactive - system exposed to network threats")
      end
    elsif command_exists?("firewall-cmd")
      if cmd_output("firewall-cmd --state 2>/dev/null").include?("running")
        evaluate_status("Firewall Status (firewalld)", "PASS", "Firewalld active and protecting system")
      else
        evaluate_status("Firewall Status (firewalld)", "FAIL", "Firewalld inactive - system exposed to network threats")
      end
    elsif command_exists?("iptables")
      if cmd_output("iptables -L -n").include?("Chain INPUT")
        evaluate_status("Firewall Status (iptables)", "PASS", "iptables rules active and protecting system")
      else
        evaluate_status("Firewall Status (iptables)", "FAIL", "No active iptables rules detected - system may be exposed")
      end
    elsif command_exists?("nft")
      if cmd_output("nft list ruleset").include?("table")
        evaluate_status("Firewall Status (nftables)", "PASS", "nftables rules active and protecting system")
      else
        evaluate_status("Firewall Status (nftables)", "FAIL", "No active nftables rules detected - system may be exposed")
      end
    else
      evaluate_status("Firewall Status", "FAIL", "No recognized firewall tools detected on system")
    end
  end

  def check_unattended_upgrades
    if cmd_output("dpkg -l").include?("unattended-upgrades")
      evaluate_status("Unattended Upgrades", "PASS", "Automatic updates configured")
    else
      evaluate_status("Unattended Upgrades", "FAIL", "Automatic updates not configured - system may miss critical patches")
    end
  end

  def check_intrusion_prevention
    ips_installed = false
    ips_active = false

    if cmd_output("dpkg -l").include?("fail2ban")
      ips_installed = true
      ips_active = system("systemctl is-active fail2ban >/dev/null 2>&1")
    end

    if command_exists?("docker") && system("systemctl is-active --quiet docker")
      if cmd_output("docker ps -a").split("\n").any? { |line| line.include?("fail2ban") }
        ips_installed = true
        ips_active = cmd_output("docker ps").include?("fail2ban")
      end
      if cmd_output("docker ps -a").split("\n").any? { |line| line.include?("crowdsec") }
        ips_installed = true
        ips_active = cmd_output("docker ps").include?("crowdsec")
      end
    elsif command_exists?("docker")
      evaluate_status("Intrusion Prevention", "WARN", "Docker installed but not running - cannot check for Fail2ban containers")
    end

    if cmd_output("dpkg -l").include?("crowdsec")
      ips_installed = true
      ips_active = system("systemctl is-active crowdsec >/dev/null 2>&1")
    end

    case "#{ips_installed ? 1 : 0}#{ips_active ? 1 : 0}"
    when "11"
      evaluate_status("Intrusion Prevention", "PASS", "Fail2ban or CrowdSec installed and running")
    when "10"
      evaluate_status("Intrusion Prevention", "WARN", "Fail2ban or CrowdSec installed but not running")
    else
      evaluate_status("Intrusion Prevention", "FAIL", "No intrusion prevention system detected")
    end
  end

  def check_failed_logins
    log_file = "/var/log/auth.log"

    if File.exist?(log_file)
      failed_logins = cmd_output("grep -c 'Failed password' #{log_file} 2>/dev/null || echo 0").strip.to_i
    else
      failed_logins = 0
      evaluate_status("Auth Log", "WARN", "Log file #{log_file} not found or unreadable. Assuming 0 failed attempts.")
    end

    case
    when failed_logins < 10
      evaluate_status("Failed Logins", "PASS", "Only #{failed_logins} failed attempts detected - within normal range")
    when failed_logins < 50
      evaluate_status("Failed Logins", "WARN", "#{failed_logins} failed attempts detected - may indicate intrusion attempts")
    else
      evaluate_status("Failed Logins", "FAIL", "#{failed_logins} failed attempts detected - possible brute force attack")
    end
  end

  def check_system_updates
    updates = cmd_output("apt-get -s upgrade 2>/dev/null | grep -P '^\\d+ upgraded'").split.first.to_i

    if updates == 0
      evaluate_status("System Updates", "PASS", "All packages current")
    else
      evaluate_status("System Updates", "FAIL", "#{updates} updates available - system vulnerable to known exploits")
    end
  end

  def check_running_services
    services = cmd_output("systemctl list-units --type=service --state=running | grep -c 'loaded active running'").strip.to_i

    case
    when services < 20
      evaluate_status("Running Services", "PASS", "Minimal services running (#{services}) - optimal for security")
    when services < 40
      evaluate_status("Running Services", "WARN", "#{services} services running - consider reducing attack surface")
    else
      evaluate_status("Running Services", "FAIL", "Excessive services running (#{services}) - increased attack surface")
    end
  end

  def check_port_security
    listening_ports = if command_exists?("netstat")
                       cmd_output("netstat -tuln | grep LISTEN").split("\n").map { |line| line.split[3] }
                     elsif command_exists?("ss")
                       cmd_output("ss -tuln | grep LISTEN").split("\n").map { |line| line.split[4] }
                     else
                       evaluate_status("Port Scanning", "FAIL", "Neither 'netstat' nor 'ss' available on system.")
                       return
                     end

    if listening_ports.any?
      public_ports = listening_ports.map { |port| port.split(':').last }.uniq.sort
      port_count = public_ports.size
      internet_ports = port_count

      ports_str = public_ports.join(',')

      case
      when port_count < 10 && internet_ports < 3
        evaluate_status("Port Security", "PASS", "Optimal configuration (Total: #{port_count}, Public: #{internet_ports} accessible ports): #{ports_str}")
      when port_count < 20 && internet_ports < 5
        evaluate_status("Port Security", "WARN", "Review recommended (Total: #{port_count}, Public: #{internet_ports} accessible ports): #{ports_str}")
      else
        evaluate_status("Port Security", "FAIL", "High exposure (Total: #{port_count}, Public: #{internet_ports} accessible ports): #{ports_str}")
      end
    else
      evaluate_status("Port Scanning", "WARN", "Port scanning failed due to missing tools. Ensure 'ss' or 'netstat' is installed.")
    end
  end

  def check_disk_usage
    df_output = cmd_output("df -h /")
    if df_output.nil? || df_output.strip.empty?
      evaluate_status("Disk Usage", "FAIL", "Unable to retrieve disk information")
      return
    end

    df_lines = df_output.split("\n")
    if df_lines.length < 2
      evaluate_status("Disk Usage", "FAIL", "Invalid disk information format")
      return
    end

    disk_info = df_lines[1].split
    if disk_info.length < 5
      evaluate_status("Disk Usage", "FAIL", "Unable to parse disk information")
      return
    end

    disk_total = disk_info[1]
    disk_used = disk_info[2]
    disk_avail = disk_info[3]
    disk_usage = disk_info[4].to_i

    case
    when disk_usage < 50
      evaluate_status("Disk Usage", "PASS", "Sufficient disk space available (#{disk_usage}% used - Used: #{disk_used} of #{disk_total}, Available: #{disk_avail})")
    when disk_usage < 80
      evaluate_status("Disk Usage", "WARN", "Moderate disk usage (#{disk_usage}% used - Used: #{disk_used} of #{disk_total}, Available: #{disk_avail})")
    else
      evaluate_status("Disk Usage", "FAIL", "Critical disk usage (#{disk_usage}% used - Used: #{disk_used} of #{disk_total}, Available: #{disk_avail})")
    end
  end

  def check_memory_usage
    free_output = cmd_output("free -h")
    if free_output.nil? || free_output.strip.empty?
      evaluate_status("Memory Usage", "FAIL", "Unable to retrieve memory information")
      return
    end

    mem_lines = free_output.split("\n")
    if mem_lines.length < 2
      evaluate_status("Memory Usage", "FAIL", "Invalid memory information format")
      return
    end

    mem_info = mem_lines[1].split
    if mem_info.length < 3
      evaluate_status("Memory Usage", "FAIL", "Unable to parse memory information")
      return
    end

    mem_total = mem_info[1]
    mem_used = mem_info[2]
    mem_avail = cmd_output("free -h | awk '/^Mem:/ {print $7}'").strip
    mem_usage = cmd_output("free | awk '/^Mem:/ {printf \"%.0f\", $3/$2 * 100}'").to_i

    case
    when mem_usage < 50
      evaluate_status("Memory Usage", "PASS", "Optimal memory usage (#{mem_usage}% used - Used: #{mem_used} of #{mem_total}, Available: #{mem_avail})")
    when mem_usage < 80
      evaluate_status("Memory Usage", "WARN", "Elevated memory usage (#{mem_usage}% used - Used: #{mem_used} of #{mem_total}, Available: #{mem_avail})")
    else
      evaluate_status("Memory Usage", "FAIL", "Critical memory usage (#{mem_usage}% used - Used: #{mem_used} of #{mem_total}, Available: #{mem_avail})")
    end
  end

  def check_cpu_usage
    cpu_cores = cmd_output("nproc").strip

    top_output = cmd_output("top -bn1 | grep 'Cpu(s)'")
    cpu_usage = 0
    cpu_idle = 100

    if !top_output.nil? && !top_output.strip.empty?
      cpu_usage = top_output.match(/(\d+\.\d+)%us/)[1].to_i rescue 0
      cpu_idle = top_output.match(/(\d+\.\d+)%id/)[1].to_i rescue 100
    end

    uptime_output = cmd_output("uptime")
    cpu_load = "Unknown"

    if !uptime_output.nil? && !uptime_output.strip.empty?
      load_parts = uptime_output.split('load average:')
      if load_parts.length > 1 && !load_parts[1].nil?
        load_values = load_parts[1].split(',')
        cpu_load = load_values[0].strip if load_values.length > 0
      end
    end

    case
    when cpu_usage < 50
      evaluate_status("CPU Usage", "PASS", "Optimal CPU usage (#{cpu_usage}% used - Active: #{cpu_usage}%, Idle: #{cpu_idle}%, Load: #{cpu_load}, Cores: #{cpu_cores})")
    when cpu_usage < 80
      evaluate_status("CPU Usage", "WARN", "Elevated CPU usage (#{cpu_usage}% used - Active: #{cpu_usage}%, Idle: #{cpu_idle}%, Load: #{cpu_load}, Cores: #{cpu_cores})")
    else
      evaluate_status("CPU Usage", "FAIL", "Critical CPU usage (#{cpu_usage}% used - Active: #{cpu_usage}%, Idle: #{cpu_idle}%, Load: #{cpu_load}, Cores: #{cpu_cores})")
    end
  end

  def check_sudo_logging
    if cmd_output("grep '^Defaults.*logfile' /etc/sudoers 2>/dev/null").strip.length > 0
      evaluate_status("Sudo Logging", "PASS", "Sudo commands being logged for monitoring purposes")
    else
      evaluate_status("Sudo Logging", "FAIL", "Sudo commands not being logged - reduces oversight capability")
    end
  end

  def check_password_policy
    if File.exist?("/etc/security/pwquality.conf")
      if cmd_output("grep 'minlen.*12' /etc/security/pwquality.conf 2>/dev/null").strip.length > 0
        evaluate_status("Password Policy", "PASS", "Strong password policy enforced")
      else
        evaluate_status("Password Policy", "FAIL", "Weak password policy - passwords may be insufficient")
      end
    else
      evaluate_status("Password Policy", "FAIL", "No password policy configured - system accepts weak passwords")
    end
  end

  def check_suid_files
    common_suid_paths = '^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
    known_suid_bins = 'ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

    suid_files = cmd_output("find / -type f -perm -4000 2>/dev/null | grep -v -E '#{common_suid_paths}' | grep -v -E '#{known_suid_bins}' | wc -l").strip.to_i

    if suid_files == 0
      evaluate_status("SUID Files", "PASS", "No suspicious SUID files detected - excellent security practice")
    else
      evaluate_status("SUID Files", "WARN", "Found #{suid_files} SUID files outside standard locations - verify legitimacy")
    end
  end

  def finalize_report
    File.open(@report_file, 'a') do |f|
      f.puts "================================"
      f.puts "System Information Summary:"
      f.puts "Hostname: #{cmd_output('hostname').strip}"
      f.puts "Kernel: #{cmd_output('uname -r').strip}"
      f.puts "OS: #{cmd_output("grep PRETTY_NAME /etc/os-release").split('"')[1] rescue 'Unknown'}"
      f.puts "CPU Cores: #{cmd_output('nproc').strip}"
      f.puts "Total Memory: #{cmd_output("free -h | awk '/^Mem:/ {print $2}'").strip}"
      f.puts "Total Disk Space: #{cmd_output("df -h / | awk 'NR==2 {print $2}'").strip}"
      f.puts "================================"
      f.puts "Assessment Complete"
      f.puts "Review findings and implement recommended security measures."
    end

    puts "\nSecurity assessment completed. Report saved to #{@report_file}"
    puts "Please review #{@report_file} for security recommendations."
  end

  def cmd_output(command)
    `#{command}` rescue ""
  end

  def command_exists?(command)
    system("command -v #{command} >/dev/null 2>&1")
  end

  def get_public_ip
    uri = URI('https://api.ipify.org')
    Net::HTTP.get(uri) rescue "Unknown"
  end
end

if __FILE__ == $0
  auditor = ServerAuditor.new
  auditor.run
end
