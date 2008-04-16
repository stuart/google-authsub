# GoogleAuthSub - Ruby on Rails plugin for Google Authorization
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


require File.dirname(__FILE__) + '/spec_helper'
require 'fake_web'
require 'net/http'
require 'openssl'

include GData 

describe GoogleAuthSub do

  before do

    @test_next_url = "http://www.example.com/next"
    @test_scope_url = "http://www.google.com/calendar/feeds"
    
    # Valid test token
    @token = TOKEN
    
    # Invalid test token
    @invalid_token = INVALID_TOKEN
    @session_token = SESSION_TOKEN
 
    # Various URLs we expect to call
    @valid_request_url = AUTHSUB_REQUEST_URL + "?next=http://www.example.com/next&scope=http://www.google.com/calendar/feeds&session=0&secure=0"
    @valid_session_request_url = AUTHSUB_REQUEST_URL + "?next=http://www.example.com/next&scope=http://www.google.com/calendar/feeds&session=1&secure=0"
    @valid_secure_session_url = AUTHSUB_REQUEST_URL + "?next=http://www.example.com/next&scope=http://www.google.com/calendar/feeds&session=1&secure=1"
    @session_token_request_url = AUTHSUB_SESSION_TOKEN_URL
    @token_revoke_url = AUTHSUB_REVOKE_TOKEN_URL
    @token_info_url = AUTHSUB_TOKEN_INFO_URL
    @data_request_url = @test_scope_url + "/default/private/full"

    @authsub = GoogleAuthSub.new({:next_url => @test_next_url, :scope_url => @test_scope_url})
  end

  describe "Methods GoogleAuthsubToken should have" do

    it "should have a request_url method" do
      @authsub.should respond_to(:request_url)
    end

    it "should have a get_session_token method" do
      @authsub.should respond_to(:session_token)
    end

    it "should have an revoke_token method" do
      @authsub.should respond_to(:revoke_token)
    end

    it "should have a token_info method" do
      @authsub.should respond_to(:token_info)
    end

    it "should have a get method" do
      @authsub.should respond_to(:get)
    end
    
    it "should have a post method" do
      @authsub.should respond_to(:post)
    end
    
    it "should have a put method" do
      @authsub.should respond_to(:put)
    end
    
    it "should have a delete method" do
      @authsub.should respond_to(:delete)
    end
  end

  describe "Request method - getting a single use token from Google" do

    it "should redirect to request url" do
      @authsub.request_url.to_s.should == @valid_request_url
    end

    it "should redirect to request url with session = true" do
      @authsub.session = true
      @authsub.request_url.to_s.should == @valid_session_request_url
    end

    it "should redirect to request url with secure = true" do
      @authsub.session = true
      @authsub.secure = true
      @authsub.request_url.to_s.should == @valid_secure_session_url
     end

    it 'should raise an error if the scope URL is not a full path' do
      @authsub.scope = "www.google.com/calendar/feeds"
      lambda { @authsub.request_url }.should raise_error(AuthSubError)
    end
    
    it "should raise an error if the next_url is not a full path" do
      @authsub.next_url = "www.schedy.com" 
      lambda { @authsub.request_url }.should raise_error(AuthSubError)
    end
  end

  describe "Token Signatures" do
    before(:all) do
      # Private key for signing
      f = File.open(File.dirname(__FILE__)+"/mock_certs/test_private_key.pem")
      @private_key = OpenSSL::PKey::RSA.new(f.read)
      @public_key = @private_key.public_key
      GoogleAuthSub.set_private_key(@private_key)
    end
    
    before do
       Time.stub!(:now).and_return(Time.local(2008,"mar",8,12,15,1))
       OpenSSL::BN.stub!(:rand_range).and_return(100000000000000)
       FakeWeb.register_uri(@data_request_url, :response => File.dirname(__FILE__)+"/mock responses/calendar.txt")
       @authsub.secure = true
       @authsub.token = @token 
       @header = @authsub.auth_header(Net::HTTP::Get, @data_request_url)
       @data = @authsub.auth_data(Net::HTTP::Get, @data_request_url) 
       @sig = @authsub.sig(@header)
    end
    
    it "should have a signing algorithm" do
      @authsub.should respond_to(:sigalg)
    end
    
    it "should have rsa-sha1 as the sigalg" do
      @authsub.sigalg.should == 'rsa-sha1'
    end
    
    it "should generate a correct authorization header when not secure" do
      @authsub.secure = false
      @authsub.auth_header(Net::HTTP::Get, @data_request_url).should == "AuthSub token=\"#{@token}\""
    end
    
    it "should generate a correct authorization header when secure" do
       @authsub.auth_header(Net::HTTP::Get, @data_request_url).should match(/AuthSub token="#{@token}" sigalg="rsa-sha1" data="(.)*" sig=(.)*$/)
    end
     
    it "should have a valid data section in authorization header" do
      @authsub.auth_data(Net::HTTP::Get, @data_request_url).should match(/^GET #{@data_request_url} #{Time.now.to_i} 100000000000000$/)
    end
    
    it "should generate the correct signature for the token" do
      @sig.should == Base64.b64encode(@private_key.sign(OpenSSL::Digest::SHA1.new,@data))
      #@public_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(@sig), @data).should be_true
    end
    
    it "should take private key as a  file" do
      f = File.open(File.dirname(__FILE__)+"/mock_certs/test_private_key.pem")
      GoogleAuthSub.set_private_key(f)
    end 
    
    it "should take private key as a string" do
      s = File.open(File.dirname(__FILE__)+"/mock_certs/test_private_key.pem").read
      GoogleAuthSub.set_private_key(s)
    end
    
  end

  describe "Token received from Google in response url. Note: in Rails this is simply params[:token]" do
    before do
     url = URI::HTTP.build({:host => "www.example.com", :path => "/next", :query => "Token=#{@token}"})
     @authsub.receive_token(url)
    end
    
    it "should find the token in the headers and save it" do
      @authsub.token.should == @token
    end
    
    it "should retain current token value if no token is found" do
      url = URI::HTTP.build({:host => "www.example.com", :path => "/next", :query => ""})
      @authsub.receive_token(url)
      @authsub.token.should == @token
    end
    
  end

  describe "Getting a session token from google" do
    before do
      FakeWeb.register_uri(@session_token_request_url, :response => File.dirname(__FILE__)+"/mock responses/session_token.txt")
    end
    
    it "should make request to correct url" do
      FakeWeb.should_receive(:response_for).with(@session_token_request_url).
      and_return(FakeWeb::Registry.instance.response_for(@session_token_request_url))
      @authsub.session_token
    end

  end

  describe "Succesful receipt of a session token" do
    before do
      FakeWeb.register_uri(@session_token_request_url, :response =>  File.dirname(__FILE__)+"/mock responses/session_token.txt")
    end
    
    it "should set session_token in session to correct value" do
      @authsub.session_token
      @authsub.token.should == @session_token
    end
  end

  describe "Unsuccessful request for session token - revoked token" do
      it "should raise a server exception error" do
        FakeWeb.register_uri(@session_token_request_url, :response =>  File.dirname(__FILE__)+"/mock responses/revoked_token.txt")
        lambda {
          @authsub.session_token
        }.should raise_error(AuthSubError)
      end
  end

  describe "Revoking a session token" do
    before do
      FakeWeb.register_uri(@token_revoke_url, :response => File.dirname(__FILE__)+"/mock responses/revoke_token.txt")
      @authsub.token = @token
    end
    
    it "should make request to correct url" do
       FakeWeb.should_receive(:response_for).with(@token_revoke_url).
       and_return(FakeWeb::Registry.instance.response_for(@token_revoke_url))
       @authsub.revoke_token
     end
     
     it "should return true" do
      @authsub.revoke_token.should be_true
     end
     
     it "should return false on an error" do
       FakeWeb.register_uri(@token_revoke_url, :response => File.dirname(__FILE__)+"/mock responses/unauthorized.txt")
       @authsub.revoke_token.should be_false
     end
  end

  describe "Getting token info from google" do
    before do
      FakeWeb.register_uri(@token_info_url, :response => File.dirname(__FILE__)+"/mock responses/token_info.txt")
      @authsub.token = @token
    end
    
    it "should make request to correct url" do
      FakeWeb.should_receive(:response_for).with(@token_info_url).
          and_return(FakeWeb::Registry.instance.response_for(@token_info_url))
      @authsub.token_info
    end
    
    it "should return the info as [:target => target, :scope=> scope, :secure=> secure]" do
      @authsub.token_info.should == {:target=>'http://www.example.com', 
                                             :scope=>'http://www.google.com/calendar/feeds/', 
                                             :secure=>true}                                          
    end
    
    it "should throw an error on an incorrect response from Google" do
      FakeWeb.register_uri(@token_info_url, :response => File.dirname(__FILE__)+"/mock responses/bad_token_info.txt")
      lambda{
        @authsub.token_info
      }.should raise_error(AuthSubError)
    end
  end


  describe "Get data from google using the token" do
    before do
      FakeWeb.register_uri(@data_request_url, :response => File.dirname(__FILE__)+"/mock responses/calendar.txt")
    end
    
    it "should append the scope to the url when it does not start with http://" do
      FakeWeb.should_receive(:response_for).with(@data_request_url).
        and_return(FakeWeb::Registry.instance.response_for(@data_request_url))
      @authsub.get("/default/private/full")
    end
    
    it "should raise errors if there is an error in the response" do 
      FakeWeb.register_uri(@data_request_url, :response => File.dirname(__FILE__)+"/mock responses/unauthorized.txt")
      lambda{@authsub.get(@data_request_url)}.should raise_error(Net::HTTPServerException)
    end
    
    it "should pass the entire response as a Net::HTTPResponse object" do
      @authsub.get(@data_request_url).should be_a_kind_of(Net::HTTPResponse)
    end
    
    it "should have the correct body" do
      @authsub.get(@data_request_url).body.should == "This is my wonderful calendar!\nEmpty as usual.\nHire me!!"
    end
  end
  
  describe "Post Data to Goole using the token" do
      before do
         FakeWeb.register_uri(@data_request_url, :response => File.dirname(__FILE__)+"/mock responses/calendar.txt")
      end 

      it "should append the scope to the url when it does not start with http://" do
        FakeWeb.should_receive(:response_for).with(@data_request_url).
          and_return(FakeWeb::Registry.instance.response_for(@data_request_url))
        @authsub.post("/default/private/full")
      end

      it "should raise errors if there is an error in the response" do 
        FakeWeb.register_uri(@data_request_url, :response => File.dirname(__FILE__)+"/mock responses/unauthorized.txt")
        lambda{@authsub.post(@data_request_url)}.should raise_error(Net::HTTPServerException)
      end

      it "should pass the entire response as a Net::HTTPResponse object" do
        @authsub.post(@data_request_url).should be_a_kind_of(Net::HTTPResponse)
      end

      it "should have the correct body" do
        @authsub.post(@data_request_url).body.should == "This is my wonderful calendar!\nEmpty as usual.\nHire me!!"
      end
  end
  
  
end
