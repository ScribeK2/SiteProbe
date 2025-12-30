class CreateDomainChecks < ActiveRecord::Migration[8.1]
  def change
    create_table :domain_checks do |t|
      t.string :domain, null: false, index: true
      t.json :whois_data
      t.json :dns_data
      t.json :ssl_data
      t.json :email_data
      t.string :status, default: "pending", null: false
      t.references :user, null: false, foreign_key: true

      t.timestamps
    end
  end
end
