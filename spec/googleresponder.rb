#!/usr/bin/env ruby

# Currently unused...
require 'webrick'
include WEBrick

s = HTTPServer.new( :Port => 2000,
                    :SSLEnable => true
                  )

class AuthEchoServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    res.body = req[Authorization]
    res['Content-Type'] = "text/html"
    
  end
  
  def do_PUT(req,res)
  
  end
end
s.mount("/accounts", AuthEchoServlet)


trap("INT"){ s.shutdown }
s.start