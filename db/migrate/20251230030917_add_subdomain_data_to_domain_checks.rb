class AddSubdomainDataToDomainChecks < ActiveRecord::Migration[8.1]
  def change
    add_column :domain_checks, :subdomain_data, :json
  end
end
