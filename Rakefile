require 'rubygems'  
require 'rake'  
  
begin  
  require 'jeweler'  
  Jeweler::Tasks.new do |gemspec|  
    gemspec.name = "google-authsub"  
    gemspec.summary = "A ruby implementation of Google Authentication for Web Applications API"  
    gemspec.description = "GoogleAuthSub provides the Google Authentications for Web Applications API."  
    gemspec.email = "stuart.coyle@gmail.com"  
    gemspec.homepage = "http://github.com/stuart/google-authsub/tree/master"  
    gemspec.authors = ["Stuart Coyle", "Jesse Storimer"]
  end  
  Jeweler::GemcutterTasks.new  
rescue LoadError  
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"  
end  
  
Dir["#{File.dirname(__FILE__)}/tasks/*.rake"].sort.each { |ext| load ext }
