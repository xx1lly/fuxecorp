#!/usr/bin/env ruby

require_relative 'lib/application'

if __FILE__ == $0
  app = Application.new
  app.main_menu
end
