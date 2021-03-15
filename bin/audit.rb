#!/usr/bin/env ruby

puts "Server Assessment Tool v0.1"
puts "Basic system check functionality"

# Basic system info gathering
hostname = `hostname`.strip
puts "System: #{hostname}"
