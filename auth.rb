require 'rubygems'
require 'bcrypt'
require 'haml'
require 'sinatra'
require 'mongo'

enable :sessions

@@conn = Mongo::Connection.new
@@db   = @@conn['hails']
@@coll = @@db['users']

helpers do
  
  def login?
    if session[:username].nil?
      return false
    else
      return true
    end
  end
  
  def username
    return session[:username]
  end
  
  def do_login(username)
    session[:username] = username
    mac = Digest::HMAC.new(ENV["HMAC_KEY"], Digest::SHA1).hexdigest(username)
    response.set_cookie("_hails_user", :value => [username, mac].join(":"),
                        :domain => ".gitstar.com",
                        :path => "/")
  end
  
end

get "/" do
  session[:redirect_to] = request.referer
  haml :index
end

get "/signup" do
  haml :signup
end

post "/signup" do
  user = @@coll.find_one("_id" => params[:username])
  if not user
    user = {"_id" => params[:username], "password" => BCrypt::Password.create(params[:password])}
    @@coll.save(user)
    session[:username] = params[:username]
    
    redirect "/"
  else
    redirect back
  end
end

post "/login" do
  user = @@coll.find_one("_id" => params[:username])
  if user and BCrypt::Password.new(user["password"]) == params[:password]
    session[:username] = params[:username]
    redirect "/"
  end
  haml :error
end

get "/logout" do
  session[:username] = nil
  redirect "/"
end

__END__
@@layout
!!! 5
%html
  %head
    %title Sinatra Authentication
  %body
  =yield
@@index
-if login?
  %h1= "Welcome #{username}!"
  %a{:href => "/logout"} Logout
-else
  %form(action="/login" method="post")
    %div
      %label(for="username")Username:
      %input#username(type="text" name="username")
    %div
      %label(for="password")Password:
      %input#password(type="password" name="password")
    %div
      %input(type="submit" value="Login")
      %input(type="reset" value="Clear")
  %p
    %a{:href => "/signup"} Signup
@@signup
%p Enter the username and password!
%form(action="/signup" method="post")
  %div
    %label(for="username")Username:
    %input#username(type="text" name="username")
  %div
    %label(for="password")Password:
    %input#password(type="password" name="password")
  %div
    %label(for="checkpassword")Password:
    %input#password(type="password" name="checkpassword")
  %div
    %input(type="submit" value="Sign Up")
    %input(type="reset" value="Clear")
@@error
%p Wrong username or password
%p Please try again!