class ExpirationNotificationJob < ApplicationJob
  queue_as :default

  # Thresholds for sending notifications (in days)
  URGENT_THRESHOLD = 7
  WARNING_THRESHOLD = 30
  NOTICE_THRESHOLD = 90

  def perform(notification_type = :weekly_summary)
    case notification_type.to_sym
    when :weekly_summary
      send_weekly_summaries
    when :urgent_alerts
      send_urgent_alerts
    else
      Rails.logger.warn "Unknown notification type: #{notification_type}"
    end
  end

  private

  def send_weekly_summaries
    User.find_each do |user|
      expiring_domains = find_expiring_domains(user, NOTICE_THRESHOLD)
      expiring_ssl = find_expiring_ssl(user, NOTICE_THRESHOLD)

      next if expiring_domains.empty? && expiring_ssl.empty?

      ExpirationMailer.weekly_summary(user, expiring_domains, expiring_ssl).deliver_later
      Rails.logger.info "Sent weekly summary to #{user.email}"
    end
  end

  def send_urgent_alerts
    User.find_each do |user|
      # Domain expiration alerts
      find_expiring_domains(user, URGENT_THRESHOLD).each do |item|
        ExpirationMailer.domain_expiring(user, item[:check], item[:days_until]).deliver_later
        Rails.logger.info "Sent urgent domain alert to #{user.email} for #{item[:domain]}"
      end

      # SSL expiration alerts
      find_expiring_ssl(user, URGENT_THRESHOLD).each do |item|
        ExpirationMailer.ssl_expiring(user, item[:check], item[:days_until]).deliver_later
        Rails.logger.info "Sent urgent SSL alert to #{user.email} for #{item[:domain]}"
      end
    end
  end

  def find_expiring_domains(user, threshold_days)
    expiring = []

    user.domain_checks.where(status: :completed).find_each do |check|
      next unless check.whois_data.present?

      whois = check.whois_data.with_indifferent_access
      next unless whois[:success] && whois[:expiration_date].present?

      begin
        expiry = Date.parse(whois[:expiration_date])
        days_until = (expiry - Date.today).to_i

        if days_until > 0 && days_until <= threshold_days
          expiring << {
            domain: check.domain,
            check: check,
            days_until: days_until,
            expiry_date: expiry
          }
        end
      rescue ArgumentError
        # Skip invalid dates
      end
    end

    expiring.sort_by { |item| item[:days_until] }
  end

  def find_expiring_ssl(user, threshold_days)
    expiring = []

    user.domain_checks.where(status: :completed).find_each do |check|
      next unless check.ssl_data.present?

      ssl = check.ssl_data.with_indifferent_access
      next unless ssl[:success] && ssl[:certificate].present?

      cert = ssl[:certificate].with_indifferent_access
      days_until = cert[:days_until_expiry]

      if days_until && days_until > 0 && days_until <= threshold_days
        expiring << {
          domain: check.domain,
          check: check,
          days_until: days_until
        }
      end
    end

    expiring.sort_by { |item| item[:days_until] }
  end
end

