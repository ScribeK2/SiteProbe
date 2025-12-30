require "test_helper"

class ChecksControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email: "test@example.com", password: "password123")
    sign_in @user
  end

  test "should get new" do
    get new_check_url
    assert_response :success
  end

  test "should create domain check" do
    assert_difference("DomainCheck.count") do
      post checks_url, params: { domain_check: { domain: "example.com" } }
    end

    check = DomainCheck.last
    assert_equal "example.com", check.domain
    assert_equal @user, check.user
    assert_redirected_to check_url(check)
  end

  test "should show domain check" do
    check = DomainCheck.create!(domain: "example.com", user: @user)
    get check_url(check)
    assert_response :success
  end

  test "should not create check with invalid domain" do
    assert_no_difference("DomainCheck.count") do
      post checks_url, params: { domain_check: { domain: "invalid-domain" } }
    end

    assert_response :unprocessable_entity
  end

  test "requires authentication" do
    sign_out @user
    get new_check_url
    assert_redirected_to new_user_session_url
  end
end
