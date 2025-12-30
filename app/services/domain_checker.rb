class DomainChecker
  def self.check(domain_check)
    new(domain_check).check
  end

  def initialize(domain_check)
    @domain_check = domain_check
    @domain = domain_check.domain
  end

  def check
    @domain_check.update(status: :processing)

    begin
      # Run core checks (these can be slow, so they're queued via DomainCheckJob)
      whois_result = WhoisChecker.check(@domain)
      dns_result = DnsChecker.check(@domain)

      # Run SSL and HTTP checks (MVP2)
      ssl_result = SslChecker.check(@domain)
      http_result = HttpChecker.check(@domain)

      # Run email authentication checks (MVP3)
      # Pass MX records from DNS check to email checker for chain checks
      mx_records = dns_result[:mx_records] if dns_result[:success]
      email_result = EmailChecker.check(@domain, mx_records: mx_records)

      # Run subdomain scan if requested
      subdomain_result = nil
      if @domain_check.scan_subdomains?
        subdomain_result = SubdomainScanner.scan(@domain)
      end

      # Update domain check with results
      @domain_check.update(
        whois_data: whois_result,
        dns_data: dns_result,
        ssl_data: ssl_result,
        http_data: http_result,
        email_data: email_result,
        subdomain_data: subdomain_result,
        status: determine_status(whois_result, dns_result)
      )

      # Broadcast update via Solid Cable
      broadcast_update
    rescue StandardError => e
      @domain_check.update(status: :failed)
      Rails.logger.error("Domain check failed: #{e.message}")
      raise
    end

    @domain_check
  end

  private

  def determine_status(whois_result, dns_result)
    # Consider the check successful if at least WHOIS or DNS succeeded
    if whois_result[:success] || dns_result[:success]
      :completed
    else
      :failed
    end
  end

  def broadcast_update
    ActionCable.server.broadcast(
      "domain_check_#{@domain_check.id}",
      {
        id: @domain_check.id,
        status: @domain_check.status,
        whois_data: @domain_check.whois_data,
        dns_data: @domain_check.dns_data,
        ssl_data: @domain_check.ssl_data,
        http_data: @domain_check.http_data,
        email_data: @domain_check.email_data,
        subdomain_data: @domain_check.subdomain_data
      }
    )
  rescue StandardError => e
    Rails.logger.error("Failed to broadcast update: #{e.message}")
  end
end

