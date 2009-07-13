# AuthSub - Ruby library for Google Authorization
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
require 'cgi'

# Note: The module declared here may change depending on what other developers are using.
#
module GData
  
    GOOGLE_HOST_URL = "www.google.com"
    GOOGLE_AUTHSUB_BASE_PATH = "/accounts"
    GOOGLE_AUTHSUB_REQUEST_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubRequest"
    GOOGLE_AUTHSUB_SESSION_TOKEN_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubSessionToken"
    GOOGLE_AUTHSUB_REVOKE_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubRevokeToken"
    GOOGLE_AUTHSUB_TOKEN_INFO_PATH = GOOGLE_AUTHSUB_BASE_PATH + "/AuthSubTokenInfo"

class Error < Exception
end

class AuthSubError < Error
  def message
    "Google Authentication Error"
  end
end


# GoogleAuthSub
# This class handles the Google Authentication for Web Applications API
#
class GoogleAuthSub

  attr_accessor :target, :scope, :session, :secure, :next_url, :token, :sigalg

  # +key+ can be a File, String or OpenSSL::Pkey::RSA
  # Sets the private key to use for secure sessions.
  # This should correspond to the public key sent to Google in
  # the registration process.
  # For registration details see:
  #   http://code.google.com/apis/accounts/docs/RegistrationForWebAppsAuto.html
  #
  # This sets the class variable @@pkey to an OpenSSL::Pkey::RSA object
  # 
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
         raise AuthSubError, "Private Key in wrong format. Require IO, String or OpenSSL::Pkey::RSA, you gave me #{key.class}"
     end
  end

  # Create a new GoogleAuthsub object
  # Options specified in +opts+ consist of:
  #
  # * :next_url - (String)  The url to redirect back to once the user has signed in to Google.
  # * :scope_url - (String) The service from Google that you wish to receive data from with this token.
  # * :session - (boolean)  Whether the token is able to be used to get a session token or is just one use.
  # * :secure - (boolean) Whether the token can be used for sessions.
  # * :sigalg - (String) Currently not needed, as the Authsub specification only has rsa-sha1.  
  def initialize(opts = {})
    self.next_url = opts[:next_url] || ''
    self.scope = opts[:scope_url] || ''
    self.session = opts[:session] || false
    self.secure = opts[:secure] || false
    self.sigalg = opts[:sigalg] || "rsa-sha1"
  end

  # This returns a URI::HTTPS object which contains the Google url to request a token from.
  def request_url
     raise AuthSubError, "Invalid next URL: #{@next_url}" if !full_url?(@next_url)
     raise AuthSubError, "Invalid scope URL: #{@scope}" if !full_url?(@scope)
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
  # In Rails applications you don't need this method, just use
  # +GoogleAuthsub#token=params[:token]+
  #
  def receive_token(url)
      raise AuthSubError, "receive_token() was not passed a url, #{@url.class} received instead." if !url.class == URI::HTTP
      q = url.query.match( /.*token=(.*)/i) if !url.query.nil?
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

  # request_session_token
  # This method exchanges a previously received single use token with a session token.
  # Raises error if an invalid response is received.
  def request_session_token
   url =  URI::HTTPS.build({:host => GOOGLE_HOST_URL,
        :path => GOOGLE_AUTHSUB_SESSION_TOKEN_PATH})
   begin
     response = get(url)
   rescue
     raise AuthSubError, "Invalid session token response."
   end 
   @token = response.body.match(/^Token=(.*)$/)[1]
  end

  # revoke_token
  # This revokes either a single use or session token
  # The token will not be able to be used again if this call is successful.
  # It returns true on sucess, false on failure.
  def revoke_token
    url = URI::HTTPS.build({:host=>GOOGLE_HOST_URL,
      :path => GOOGLE_AUTHSUB_REVOKE_PATH})
    begin
     response = get(url)
     true
    rescue
     false
    end
  end

  # token_info
  # Returns the information for the session token from Google.
  # Returns a map {:target, :scope, :secure}
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
      raise AuthSubError, "Google Authsub Error: invalid token info packet received."
    end
    return info
  end

  # get +url+s
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

  # put +url+
  # Does a HTTP PUT request to Google using the AuthSub token.
  # This returns a Net::HTTPResponse object.
  def put(url)
    authsub_http_request(Net::HTTP::Put,url)
  end

  # delete +url+
  # Does a HTTP DELETE request to Google using the AuthSub token.
  # This returns a Net::HTTPResponse object.
  def delete(url)
    authsub_http_request(Net::HTTP::Delete,url)
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
      when URI
        url = u
      else
        raise AuthSubError, "url must be String or URI, #{url.class} received."
    end

    if method.superclass != Net::HTTPRequest
      raise AuthSubError, "method must be a Net::HTTPRequest subclass (GET POST PUT DELETE). #{method} received."
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

  # Construct the authorization header for a request
  def authorization_header(request, url)
    case secure_token?
    when false
      return "AuthSub token=\"#{@token}\""
    when true
      timestamp = Time.now.to_i
      nonce = OpenSSL::BN.rand_range(2**64)
      data = request.method + ' ' + url.to_s + ' ' + timestamp.to_s + ' ' + nonce.to_s
      digest = OpenSSL::Digest::SHA1.new(data).hexdigest
      sig = [@@pkey.private_encrypt(digest)].pack("m")  #Base64 encode
      return "AuthSub token=\"#{@token}\" data=\"#{data}\" sig=\"#{sig}\" sigalg=\"#{@sigalg}\""
    end
  end
  
  # Checks whether a URL is a full url, i.e. has all of scheme, host and path.
  def full_url?(url)
    # First check if it is a bad uri
    begin
      u = URI.parse(url)
    rescue URI.InvalidURIError
      return false
    end
    return false if u.scheme.nil? || u.host.nil? || u.path.nil?
    true
  end
  
end

end

