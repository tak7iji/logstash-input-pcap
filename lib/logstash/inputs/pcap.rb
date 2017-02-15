# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "socket" # for Socket.gethostname

# Generate a repeating message.
#
# This plugin is intented only as an example.

class LogStash::Inputs::Pcap < LogStash::Inputs::Base
  config_name "pcap"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain"

  # The interface you want to get data from
  config :file, :validate => :string, :required => true

  public
  def register
    require "pcap"
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)
    @client = Jruby::Pcap.open(@file)
    @logger.debug("Read from file: #{@file}")
  end # def register

  def run(queue)
    @client.each do |packet|
      @logger.debug("Packet: [#{packet.to_s}]")
      payload = { :timestamp => packet.timestamp } if packet.timestamp != nil
      payload.merge!(packet.to_hash)
      event = LogStash::Event.new(payload)
      event.set("host", @host)
      decorate(event)
      queue << event
    end
  end # def run

  def stop
  end
end # class LogStash::Inputs::Pcap
