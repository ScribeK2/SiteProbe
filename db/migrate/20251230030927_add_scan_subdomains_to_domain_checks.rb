class AddScanSubdomainsToDomainChecks < ActiveRecord::Migration[8.1]
  def change
    add_column :domain_checks, :scan_subdomains, :boolean, default: false
  end
end
