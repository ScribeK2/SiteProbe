class AddHttpDataToDomainChecks < ActiveRecord::Migration[8.1]
  def change
    add_column :domain_checks, :http_data, :json
  end
end
