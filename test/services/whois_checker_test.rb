require "test_helper"

class WhoisCheckerTest < ActiveSupport::TestCase
  test "check with valid domain" do
    # Mock the whois gem to avoid actual network calls in tests
    whois_record = Minitest::Mock.new
    registrar = Minitest::Mock.new
    registrar.expect :name, "Example Registrar"
    whois_record.expect :registrar, registrar
    whois_record.expect :expires_on, Date.today + 365.days
    whois_record.expect :nameservers, [
      OpenStruct.new(hostname: "ns1.example.com"),
      OpenStruct.new(hostname: "ns2.example.com")
    ]
    whois_record.expect :content, "Raw WHOIS data"

    Whois::Client.stub :new, ->(*) { mock_client(whois_record) } do
      result = WhoisChecker.check("example.com")
      
      assert result[:success]
      assert_equal "Example Registrar", result[:registrar]
      assert_not_nil result[:expiration_date]
      assert_equal 2, result[:nameservers].length
    end
  end

  test "check handles timeout errors gracefully" do
    Whois::Client.stub :new, ->(*) { raise Whois::TimeoutError.new("Timeout") } do
      result = WhoisChecker.check("example.com")
      
      assert_not result[:success]
      assert_match /timeout/i, result[:error].downcase
    end
  end

  test "check handles server not found errors" do
    Whois::Client.stub :new, ->(*) { raise Whois::ServerNotFound.new("Server not found") } do
      result = WhoisChecker.check("invalid-domain-12345.com")
      
      assert_not result[:success]
      assert_match /server not found/i, result[:error].downcase
    end
  end

  private

  def mock_client(whois_record)
    client = Minitest::Mock.new
    client.expect :lookup, whois_record, [String]
    client
  end
end

