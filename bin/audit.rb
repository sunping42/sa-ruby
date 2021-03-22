#!/usr/bin/env ruby

puts "Server Assessment Tool v0.1"
puts "Basic system check functionality"

# Basic system info gathering
hostname = `hostname`.strip
puts "System: #{hostname}"

# Add some basic security checks
puts "Checking SSH configuration..."
ssh_root = `grep PermitRootLogin /etc/ssh/sshd_config`.strip
puts "SSH Root Access: #{ssh_root}"

puts "Checking for updates..."
updates = `apt list --upgradable 2>/dev/null | wc -l`.strip.to_i - 1
puts "Available updates: #{updates}"
