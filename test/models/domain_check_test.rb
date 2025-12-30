require "test_helper"

class DomainCheckTest < ActiveSupport::TestCase
  setup do
    @user = users(:one) || User.create!(email: "test@example.com", password: "password123")
  end

  test "valid domain check" do
    check = DomainCheck.new(domain: "example.com", user: @user)
    assert check.valid?
  end

  test "invalid domain format" do
    check = DomainCheck.new(domain: "not-a-valid-domain", user: @user)
    assert_not check.valid?
    assert_includes check.errors[:domain], "must be a valid domain name"
  end

  test "requires domain" do
    check = DomainCheck.new(user: @user)
    assert_not check.valid?
    assert_includes check.errors[:domain], "can't be blank"
  end

  test "default status is pending" do
    check = DomainCheck.create!(domain: "example.com", user: @user)
    assert check.pending?
  end

  test "belongs to user" do
    check = DomainCheck.create!(domain: "example.com", user: @user)
    assert_equal @user, check.user
  end
end
