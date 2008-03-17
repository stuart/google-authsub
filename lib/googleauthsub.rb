# AuthSub - Ruby on Rails plugin for Google Authorization
# # Copyright 2008 Stuart Coyle <stuart.coyle@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'uri'
require 'net/https'
require 'openssl'
require 'base64'


module GData
    GOOGLE_HOST_URL = "www.google.com"
    GOOGLE_AUTHSUB_BASE_PATH = "/accounts"
    GOOGLE_AUTHSUB_REQUEST_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubRequest"
    GOOGLE_AUTHSUB_SESSION_TOKEN_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubSessionToken"
    GOOGLE_AUTHSUB_REVOKE_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubRevokeToken"
    GOOGLE_AUTHSUB_TOKEN_INFO_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubTokenInfo"

# GoogleAuthSub
# This class handles the Google Authentication for Web Applications API 
# 
class GoogleAuthSub
 
  attr_accessor :target, :scope, :session, :secure, :next_url, :token, :sigalg
  
  # key can be a File, String or OpenSSL::Pkey::RSA
  # Sets the private key to use for secure sessions. 
  # This should corespond to the public key sent to Google in 
  # the registration process. 
  # For registration details see: 
  #   http://code.google.com/apis/accounts/docs/RegistrationForWebAppsAuto.html
  #
  # This sets the class variable @@pkey to an OpenSSL::Pkey::RSA object
  def self.set_private_key(key)
     case key
       when OpenSSL::PKey::RSA
         @@pkey = key
       when File
         # Read key from a PEM file.
         @@pkey = OpenSSL::PKey::RSA.new(key.read)
       when String
         # Get key from a PEM in the form of a string.
         @@pkey = OpenSSL::PKey::RSA.new(key)
       else
         raise "Private Key in wrong format. Require IO, String or OpenSSL::Pkey::RSA, got #{key.class}"
     end
  end
  
  # Create a new GoogleAuthsub object
  # Options specified in +opts+ consist of:
  #
  # * :next_url - (String)  The url to redirect back to once the user has signed in to Google.
  # * :scope_url - (String) The service from Google that you wish to receive data from with this token.
  # * :session - (boolean)  Wether the token is able to be used to get a session token or is just one use.
  # * :secure - (boolean) Wether the token can be used for sessions.
  #
  def initialize(opts = {})
    self.next_url = opts[:next_url] || ''
    self.scope = opts[:scope_url] || ''
    self.session = opts[:session] || false
    self.secure = opts[:secure] || false
    self.sigalg = "rsa-sha1"
  end
  
  # This returns a URI::HTTPS object which contains the Google url to request a token from.
  def request_url
     query = "next=" << @next_url << "&scope=" << @scope << "&session="<<
             (session_token? ? '1' : '0')<< "&secure="<< (secure_token? ? '1' : '0')
     query = URI.encode(query)
     URI::HTTPS.build({:host => GOOGLE_HOST_URL, :path => GOOGLE_AUTHSUB_REQUEST_PATH, :query => query })
  end
  
  # +url+ :the URL received from Google once the user has signed in.
  #
  # This method extracts the token from the request url that Google
  # sends the user back to. 
  # This url will be like: http://www.example.com/next?Token=CMDshfjfkeodf
  # In Rails you don't need this method, just use 
  # +GoogleAuthsub#token=params[:token]+
  # 
  def receive_token(url)
    q = url.query.match(/Token=(.*)/)
    @token = q[1] if !q.nil?
  end
  
  # Returns true if this token can be exchanged for a session token
  def session_token?
    session == true
  end
  
  # Returns true if the token is used for secure sessions
  def secure_token?
    secure == true
  end
  
  # session_token
  # This method exchanges a previously received single use token with a session token.
  # Raises error if an invalid response is received.
  def session_token
    url =  URI::HTTPS.build({:host => GOOGLE_HOST_URL,
        :path => GOOGLE_AUTHSUB_SESSION_TOKEN_PATH})   
    begin
     @token = get(url).body.match(/^Token=(.*)$/)[1]
   rescue
     raise "ERROR: Invalid session token response."
   end
  end
  
  # revoke_token
  # This revokes either a single use or session token
  # The token will not be able to be used again if this call is successful.
  # It returns true on sucess, false on failure.
  def revoke_token
    url = URI::HTTPS.build({:host=>GOOGLE_HOST_URL,
      :path => GOOGLE_AUTHSUB_REVOKE_PATH})
    begin
     get(url)
     true
    rescue
     false
    end
  end
  
  # token_info
  # Returns the information for the session token
  # as a map {:target, :scope, :secure} 
  def token_info
    url =  URI::HTTPS.build({:host=>GOOGLE_HOST_URL,
      :path => GOOGLE_AUTHSUB_TOKEN_INFO_PATH})
    response = get(url)
    info = Hash.new
    begin
      info[:target] = response.body.match(/^Target=(.*)$/)[1]
      info[:scope] = response.body.match(/^Scope=(.*)$/)[1]
      info[:secure] = (response.body.match(/^Secure=(.*)$/)[1].downcase == 'true')
    rescue
      raise "Google Authsub Error: invalid token info packet received."
    end
   
    return info
  end
  
  # get +url+
  # Does a HTTP GET request to Google using the AuthSub token.
  # This returns a Net::HTTPResponse object.
  def get(url)
     authsub_http_request(Net::HTTP::Get,url)
  end
  # post +url+
  # Does a HTTP POST request to Google using the AuthSub token.
  # This returns a Net::HTTPResponse object.
  def post(url)
     authsub_http_request(Net::HTTP::Post,url)
  end
  
  private
  
  def authsub_http_request(method, u) #:nodoc:
    case u
      when String 
        # Add scope
        u = (@scope << u) if @scope && !u.include?(@scope)        
        begin
          url = URI.parse(u)
        rescue URI::InvalidURIError
          raise URI::InvalidURIError
        end
        url = URI.parse(u)
      when URI
        url = u
      else 
        raise "url must be String or URI, #{url.class} received."
    end 

    request = method.new(url.path)
    request['Authorization'] = authorization_header(request, url)
    connection =  Net::HTTP.new(url.host, url.port)
    connection.use_ssl= (url.scheme == 'https')
    response = connection.start{ |http| http.request(request) }
    case response
       when Net::HTTPSuccess
         #OK
       else
         response.error!
       end
    response
  end

  # FIXME SIGN DATA NOT TOKEN!!
  def authorization_header(request, url) 
    case secure_token?
    when false
      return "AuthSub token=\"#{@token}\""
    when true
      data = authorization_data(request, url)
      sig = sign_data(data)
      return "AuthSub token=\"#{@token}\" sigalg=\"#{sigalg}\" data=\"#{data}\" sig=\"#{sig}\""
    end
  end

  def authorization_data(request, url)
    nonce = OpenSSL::BN.rand_range(2**64)
    data = request.method + ' ' + url.to_s + ' ' + Time.now.to_i.to_s + ' ' + nonce.to_s
  end
  
  def sign_data(data)
     Base64.b64encode(@@pkey.sign(OpenSSL::Digest::SHA1.new, data))
   end
end


end