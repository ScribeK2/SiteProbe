class DashboardController < ApplicationController
  def index
    @recent_checks = current_user.domain_checks
      .order(created_at: :desc)
      .limit(10)

    @stats = calculate_stats
  end

  private

  def calculate_stats
    checks = current_user.domain_checks

    total_checks = checks.count
    completed_checks = checks.where(status: :completed).count

    # Count issues across all completed checks
    critical_count = 0
    warning_count = 0
    info_count = 0

    checks.where(status: :completed).find_each do |check|
      issues = collect_issues(check)
      issues.each do |issue|
        severity = issue[:severity] || issue["severity"]
        case severity
        when "critical" then critical_count += 1
        when "warning" then warning_count += 1
        when "info" then info_count += 1
        end
      end
    end

    # Domains expiring soon
    expiring_soon = []
    checks.where(status: :completed).find_each do |check|
      next unless check.whois_data.present?

      whois = check.whois_data.with_indifferent_access
      next unless whois[:success] && whois[:expiration_date].present?

      begin
        expiry = Date.parse(whois[:expiration_date])
        days_until = (expiry - Date.today).to_i
        if days_until <= 90 && days_until >= 0
          expiring_soon << {
            domain: check.domain,
            check_id: check.id,
            expiry_date: expiry,
            days_until: days_until
          }
        end
      rescue ArgumentError
        # Skip invalid dates
      end
    end

    # SSL certificates expiring soon
    ssl_expiring = []
    checks.where(status: :completed).find_each do |check|
      next unless check.ssl_data.present?

      ssl = check.ssl_data.with_indifferent_access
      next unless ssl[:success] && ssl[:certificate].present?

      cert = ssl[:certificate].with_indifferent_access
      days_until = cert[:days_until_expiry]
      if days_until && days_until <= 90 && days_until >= 0
        ssl_expiring << {
          domain: check.domain,
          check_id: check.id,
          days_until: days_until
        }
      end
    end

    {
      total_checks: total_checks,
      completed_checks: completed_checks,
      critical_issues: critical_count,
      warning_issues: warning_count,
      info_issues: info_count,
      domains_expiring_soon: expiring_soon.sort_by { |d| d[:days_until] }.first(5),
      ssl_expiring_soon: ssl_expiring.sort_by { |d| d[:days_until] }.first(5)
    }
  end

  def collect_issues(check)
    issues = []

    %i[whois_data dns_data ssl_data http_data].each do |data_field|
      data = check.send(data_field)
      next unless data.present?

      data = data.with_indifferent_access
      issues.concat(data[:issues] || [])
    end

    issues
  end
end

