require "test_helper"

class DnsCheckerTest < ActiveSupport::TestCase
  test "check resolves A records" do
    # Mock DNS responses
    mock_resolver = Minitest::Mock.new
    
    # Mock A record response
    a_answer = Minitest::Mock.new
    a_record = Minitest::Mock.new
    a_record.expect :type, Dnsruby::Types::A
    a_record.expect :address, IPAddr.new("93.184.216.34")
    a_answer.expect :answer, [a_record]
    
    # Mock MX record response (empty)
    mx_answer = Minitest::Mock.new
    mx_answer.expect :answer, []
    
    # Mock CNAME record response (empty)
    cname_answer = Minitest::Mock.new
    cname_answer.expect :answer, []
    
    mock_resolver.expect :query, a_answer, [String, Dnsruby::Types::A]
    mock_resolver.expect :query, mx_answer, [String, Dnsruby::Types::MX]
    mock_resolver.expect :query, cname_answer, [String, Dnsruby::Types::CNAME]
    
    Dnsruby::Resolver.stub :new, ->(*) { mock_resolver } do
      result = DnsChecker.check("example.com")
      
      assert result[:success]
      assert_includes result[:a_records], "93.184.216.34"
    end
  end

  test "check handles DNS timeout errors" do
    mock_resolver = Minitest::Mock.new
    mock_resolver.expect :query, nil, [String, Dnsruby::Types::A] do
      raise Dnsruby::Timeout.new("DNS timeout")
    end
    
    Dnsruby::Resolver.stub :new, ->(*) { mock_resolver } do
      result = DnsChecker.check("example.com")
      
      # Should still succeed if at least one resolver works
      # In this case, both will fail, so success should be false
      assert_not result[:success] || result[:errors].any?
    end
  end

  test "check handles NXDomain errors gracefully" do
    mock_resolver = Minitest::Mock.new
    
    # NXDomain for A records
    mock_resolver.expect :query, nil, [String, Dnsruby::Types::A] do
      raise Dnsruby::NXDomain.new("Domain not found")
    end
    
    # NXDomain for MX records
    mock_resolver.expect :query, nil, [String, Dnsruby::Types::MX] do
      raise Dnsruby::NXDomain.new("Domain not found")
    end
    
    # NXDomain for CNAME records
    mock_resolver.expect :query, nil, [String, Dnsruby::Types::CNAME] do
      raise Dnsruby::NXDomain.new("Domain not found")
    end
    
    Dnsruby::Resolver.stub :new, ->(*) { mock_resolver } do
      result = DnsChecker.check("nonexistent-domain-12345.com")
      
      # NXDomain is expected for non-existent domains, so this is still a successful check
      assert result[:success]
      assert_empty result[:a_records]
    end
  end
end

