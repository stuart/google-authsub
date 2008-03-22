#!/usr/local/bin/ruby
# require 'webrick'
# require 'webrick/https'
# 
# s = WEBrick::HTTPServer.new(
#   :Port            => 2000,
#   :DocumentRoot    => Dir::pwd + "/htdocs",
#   :SSLEnable       => true,
#   :SSLVerifyClient => ::OpenSSL::SSL::VERIFY_NONE,
#   :SSLCertName => [ ["C","JP"], ["O","WEBrick.Org"], ["CN", "WWW"] ]
# )
# trap("INT"){ s.shutdown }
# s.start
# 


require 'webrick'
include WEBrick

s = HTTPServer.new( :Port => 2200 
                    :SSLEnable => true
                  )

# Check the header for Valid Authentication
class AuthCheckServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    req.
    res.body = ""
    res['Content-Type'] = "text/html"
  end
end


s.mount("/accounts", TokenServlet)


trap("INT"){ s.shutdown }
s.start