require 'rake'

Gem::Specification.new do |s|
   s.name = %q{google-authsub}
   s.version = "0.0.1"
   s.date = %q{2008-03-17}
   s.authors = ["Stuart Coyle"]
   s.email = %q{stuart.coyle@gmail.com}
   s.summary = %q{A ruby implementation of Google Authentication for Web Applications API}
   s.homepage = %q{http://www.cybertherial.com/authsub}
   s.description = %q{GoogleAuthSub provides the Google Authentications for Web Applications API.}
   s.files = FileList['*.rb', 'spec/*', 'spec/**/*', '[A-Z]*'].to_a
   [ "README","MIT-LICENSE", "googleauthsub.rb", "spec/*"]
   s.has_rdoc = true
   s.rdoc_options << '--title' << '--main' << 'README' << '--line-numbers'
end