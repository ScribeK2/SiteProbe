class ExpirationMailer < ApplicationMailer
  def domain_expiring(user, domain_check, days_until_expiry)
    @user = user
    @domain_check = domain_check
    @days_until_expiry = days_until_expiry
    @domain = domain_check.domain

    mail(
      to: user.email,
      subject: "Domain expiring soon: #{@domain} (#{days_until_expiry} days)"
    )
  end

  def ssl_expiring(user, domain_check, days_until_expiry)
    @user = user
    @domain_check = domain_check
    @days_until_expiry = days_until_expiry
    @domain = domain_check.domain

    mail(
      to: user.email,
      subject: "SSL certificate expiring soon: #{@domain} (#{days_until_expiry} days)"
    )
  end

  def weekly_summary(user, expiring_domains, expiring_ssl)
    @user = user
    @expiring_domains = expiring_domains
    @expiring_ssl = expiring_ssl
    @total_issues = expiring_domains.length + expiring_ssl.length

    mail(
      to: user.email,
      subject: "SiteProbe Weekly Summary: #{@total_issues} expiration#{'s' if @total_issues != 1} upcoming"
    )
  end
end

