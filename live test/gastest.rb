#!/usr/bin/env ruby

#require 'rubygems'
require '../lib/googleauthsub'
require 'webrick'
include WEBrick
include GData

s = HTTPServer.new( :Port => 2000,
                    :SSLEnable => true
                  )

class SimpleAuthServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    @@auth.next_url="http://schedy.com:2000/simpletest"
    @@auth.receive_token(req.request_uri);
    url =  @@auth.request_url.to_s
    res.body = << END_RESPONSE
    <html><head></head><body><h2>Google-Authsub Test</h2>
    <p>TOKEN: #{req.query_string.to_s}</p>
    <p><a href= #{url}>Request GoogleAuthsub Token</a></p>
    <p><a href=/tokeninfo>Token Information</a></body></html>
    END_RESPONSE
    res['Content-Type'] = "text/html"
  end
  
end

class SessionAuthServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    @@auth.session = true
    @@auth.receive_token(req.request_uri)
    @@auth.request_session_token if !@@auth.token.nil?
    url =  @@auth.request_url.to_s
    res.body = "<html><head></head><body><h2>Google-Authsub Test</h2><p>Session Token</p><p>TOKEN: "+req.query_string.to_s+
    "</p><p><a href="+ url +
    ">Request GoogleAuthsub Token</a></p><p><a href=/tokeninfo>Token Information</a></body></html>"
    res['Content-Type'] = "text/html"
  end
end

class SecureAuthServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    @@auth.next_url="http://schedy.com:2000/sessiontest"
    @@auth.session = true
    @@auth.secure = true
    @@auth.receive_token(req.request_uri);
    url =  @@auth.request_url.to_s
    res.body = "<html><head></head><body><h2>Google-Authsub Test</h2><p>Secure Token</p><p>TOKEN: "+req.query_string.to_s+
    "</p><p><a href="+ url +
    ">Request GoogleAuthsub Token</a></p><p>INFO:<a href=/tokeninfo>Token Information</a>"
    "</body></html>"
    res['Content-Type'] = "text/html"
  end
end

class TokenInfoServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    info = @@auth.token_info
    res.body = "<html><head></head><body><h2>Google-Authsub Test</h2><p>TOKEN INFORMATION<ul>" +
    "<li>Target: "+ info[:target] + "</li>" +
    "<li>Secure: "+ info[:secure].to_s + "</li>" +
    "<li>Scope: "+ info[:scope] + "</li>" +
    "</ul></ul></p></body></html>"
    res['Content-Type'] = "text/html"
  end

class CalendarServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
     res = @@auth.get("http://www.google.com/calendar/feeds/default/owncalendars/full")
     res['Content-Type'] = "text/html"
   end
end
end

@@auth = GoogleAuthSub.new(:scope_url=>"http://www.google.com/calendar/feeds");
#s.mount("/authsub_test",AuthSub1Servlet)
#s.mount("/authsub_test_2",AuthSub2Servlet)

# Assume we have the private key in the file google.key
GoogleAuthSub.set_private_key("google.key")

s.mount("/simpletest", SimpleAuthServlet)
s.mount("/tokeninfo",TokenInfoServlet)
s.mount("/sessiontest", SessionAuthServlet)
s.mount("/securetest", SecureAuthServlet)
s.mount("/mycalendars", CalendarServlet)

trap("INT"){ s.shutdown }
s.start