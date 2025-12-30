class CreateFeedbacks < ActiveRecord::Migration[8.1]
  def change
    create_table :feedbacks do |t|
      t.references :domain_check, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.integer :accuracy_rating
      t.text :comments

      t.timestamps
    end
  end
end
