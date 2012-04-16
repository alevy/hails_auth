require './auth'
set :protection, :except => [:remote_token, :frame_options]
run Sinatra::Application