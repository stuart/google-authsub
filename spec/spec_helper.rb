
dir = File.dirname(__FILE__)
base_dir = "#{dir}/.."

require base_dir + '/googleauthsub.rb'

# Some constants for testing purposes
INVALID_TOKEN = "CMSdfhfhfjsjskee__d"
TOKEN = "CMScoaHmDxC80Y2pAg"
SESSION_TOKEN ="CMScoaHmDxDM9dqPBA"


module GData
  class GoogleAuthSub    
    # Some helper methods to break into Authsub and check a few inner workings.
    # I know it breaks encapsulation, so don't complain!
    
    # auth_header
    # Check what authorization header we are sending.
    # method is Net::HTTP::Get or Net::HTTP::Post
    def auth_header(method, url)
      url = URI.parse(url)
      request = method.new(url.path)
      authorization_header(request, url)
    end
    
    # check the auth_data section of the header
    def auth_data(method,url)
      url = URI.parse(url)
      request = method.new(url.path)
      authorization_data(request,url)
    end
    
    # extract signature from header
    def sig(header)
      s = header.match(/^.*sig="(.*)"/m)
      s[1] if !s.nil?
    end
  end
end