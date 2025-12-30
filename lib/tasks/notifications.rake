namespace :notifications do
  desc "Send weekly expiration summary emails"
  task weekly_summary: :environment do
    puts "Sending weekly expiration summaries..."
    ExpirationNotificationJob.perform_later(:weekly_summary)
    puts "Job enqueued."
  end

  desc "Send urgent expiration alerts (domains/SSL expiring within 7 days)"
  task urgent_alerts: :environment do
    puts "Sending urgent expiration alerts..."
    ExpirationNotificationJob.perform_later(:urgent_alerts)
    puts "Job enqueued."
  end

  desc "Check for expirations and send appropriate notifications"
  task check_expirations: :environment do
    puts "Checking for expirations..."
    
    # Send urgent alerts for anything expiring within 7 days
    ExpirationNotificationJob.perform_later(:urgent_alerts)
    
    puts "Notification jobs enqueued."
  end
end

