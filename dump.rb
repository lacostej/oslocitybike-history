require_relative 'utils.rb'
require 'json'
require 'time'

STDOUT.sync = true

def fetch_url(path, token: nil)
	token ||= ENV["BYSYKKEL_TOKEN"]
	raise "missing token" unless token
	url = "https://oslobysykkel.no/api/v1#{path}"
	body = WWTK::Utils.page_content(url, request_headers: {'Client-Identifier' => token})
	body
end

def dump_availability(token: nil)
	body = fetch_url("/stations/availability", token: token)
	json = JSON.parse(body)

	updated_at = Time.parse(json['updated_at'])
	refresh_rate = json['refresh_rate'].to_f
	Dir.mkdir 'data' unless Dir.exist? 'data'
	output = "data/availability_#{updated_at.to_i}.json"
	if File.exist? output
		puts "File #{output} already exists"
	else
		puts "-> Saving #{output}"
		File.write(output, body)
	end
	next_update = updated_at + refresh_rate.ceil
	next_update
end

now = Time.now
max = now + 60

while true
  next_update = dump_availability + 1
  puts "now: #{now.to_i} next_update: #{next_update.to_i}"
  break if next_update.to_i > max.to_i
  sleep_time = next_update - Time.now
# sometimes oslobysykkel refresh_rate isn't respected, let's try to not hammer their servers too much
  sleep_time = 1 if sleep_time < 0
  sleep(sleep_time)
  now = Time.now
end

puts "Ending..."
