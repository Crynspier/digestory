# frozen_string_literal: true

require_relative "../test_helper"
require "net/http"
require "socket"
require "openssl"
require "open3"
require "uri"

class HttpInteropTest < Minitest::Test
  REALM = "digestory-test@example.invalid"
  NONCE = "6f4a2e0e9e3dd9d9f6e7b0f4b2b8c1d7"
  OPAQUE = "digestory"
  USER = "Mufasa"
  PASSWORD = "Circle of Life"
  CHALLENGE = %Q{Digest realm="#{REALM}", qop="auth", algorithm=SHA-256, nonce="#{NONCE}", opaque="#{OPAQUE}"}

  class Server
    attr_reader :port

    def initialize(requests: 2)
      @server = TCPServer.new("127.0.0.1", 0)
      @port = @server.addr[1]
      @requests = requests
      @thread = Thread.new { run }
      @thread.abort_on_exception = true
    end

    def join
      @thread.join
      @server.close unless @server.closed?
    end

    private

    def run
      @requests.times do
        socket = @server.accept
        request = read_request(socket)
        if request[:authorization]
          response = verify_authorization(request)
          write_response(socket, response ? "200 OK" : "401 Unauthorized", response ? "ok" : "bad digest", response ? nil : { "WWW-Authenticate" => CHALLENGE })
        else
          write_response(socket, "401 Unauthorized", "challenge", { "WWW-Authenticate" => CHALLENGE })
        end
      ensure
        socket&.close
      end
    end

    def read_request(socket)
      data = +""
      until data.include?("\r\n\r\n")
        data << socket.readpartial(4096)
      end
      head = data.split("\r\n\r\n", 2).first
      lines = head.split("\r\n")
      method, target, _version = lines.shift.split(" ", 3)
      headers = {}
      lines.each do |line|
        key, value = line.split(":", 2)
        headers[key.downcase] = value.strip
      end
      { method: method, target: target, headers: headers, authorization: headers["authorization"] }
    rescue EOFError
      { method: nil, target: nil, headers: {}, authorization: nil }
    end

    def write_response(socket, status, body, headers = nil)
      headers ||= {}
      header_lines = {
        "Content-Length" => body.bytesize.to_s,
        "Connection" => "close",
        "Content-Type" => "text/plain"
      }.merge(headers)
      socket.write("HTTP/1.1 #{status}\r\n")
      header_lines.each { |key, value| socket.write("#{key}: #{value}\r\n") }
      socket.write("\r\n#{body}")
    end

    def verify_authorization(request)
      params = parse_authorization(request[:authorization])
      return false unless params["username"] == USER
      return false unless params["realm"] == REALM
      return false unless params["nonce"] == NONCE
      return false unless params["opaque"] == OPAQUE
      return false unless params["algorithm"] == "SHA-256"
      return false unless params["qop"] == "auth"
      return false unless params["nc"]&.match?(/\A[0-9a-f]{8}\z/i)
      return false if params["cnonce"].to_s.empty?
      return false if params["response"].to_s.empty?

      ha1 = OpenSSL::Digest::SHA256.hexdigest("#{USER}:#{REALM}:#{PASSWORD}")
      ha2 = OpenSSL::Digest::SHA256.hexdigest("#{request[:method]}:#{request[:target]}")
      expected = OpenSSL::Digest::SHA256.hexdigest("#{ha1}:#{NONCE}:#{params["nc"]}:#{params["cnonce"]}:auth:#{ha2}")
      secure_compare(expected, params["response"])
    end

    def parse_authorization(header)
      value = header.sub(/\ADigest\s+/i, "")
      result = {}
      value.scan(/([A-Za-z][A-Za-z0-9_-]*)=(?:"((?:\\.|[^"])*)"|([^, ]+))/) do |key, quoted, token|
        value_part = quoted || token
        result[key.downcase] = value_part.to_s.gsub(/\\(["\\])/, '\\1')
      end
      result
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      result = 0
      a.bytes.zip(b.bytes) { |x, y| result |= (x ^ y) }
      result.zero?
    end
  end

  def test_digestory_over_real_net_http
    server = Server.new(requests: 2)
    uri = URI("http://127.0.0.1:#{server.port}/resource?x=1")
    http = Net::HTTP.new(uri.host, uri.port)
    response = http.get(uri.request_uri)
    assert_equal "401", response.code

    session = Digestory::Session.new(username: USER, password: PASSWORD)
    authorization = session.authorize(challenge: response["www-authenticate"], method: "GET", uri: uri)
    request = Net::HTTP::Get.new(uri.request_uri)
    request["Authorization"] = authorization
    response = http.request(request)
    assert_equal "200", response.code
    assert_equal "ok", response.body
  ensure
    server&.join
  end

  def test_curl_digest_interoperability
    skip "curl not available" unless system("command -v curl >/dev/null 2>&1")
    server = Server.new(requests: 2)
    url = "http://127.0.0.1:#{server.port}/resource?x=1"
    stdout, stderr, status = Open3.capture3("curl", "--silent", "--show-error", "--digest", "--user", "#{USER}:#{PASSWORD}", url)
    assert status.success?, stderr
    assert_equal "ok", stdout
  ensure
    server&.join
  end
end
