class DomainCheckJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: 5.seconds, attempts: 3

  def perform(domain_check_id)
    domain_check = DomainCheck.find(domain_check_id)
    DomainChecker.check(domain_check)
  end
end

