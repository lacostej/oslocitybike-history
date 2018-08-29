require_relative 'utils.rb'
require 'JSON'
require 'time'

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
	output = "data/availability_#{updated_at.to_i}.json"
	if File.exist? output
		puts "File #{output} already exists"
	else
		puts "Saving #{output}"
		File.write(output, body)
	end
	next_update = updated_at + refresh_rate.ceil
	next_update
end

now = Time.now
max = now + 60

while true
  next_update = dump_availability + 1
  break if next_update.to_i > max.to_i
  sleep_time = next_update - Time.now
  sleep(sleep_time) unless sleep_time < 0
  now = Time.now
end
