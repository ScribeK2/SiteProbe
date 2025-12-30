class Feedback < ApplicationRecord
  belongs_to :domain_check
  belongs_to :user

  validates :accuracy_rating, presence: true, inclusion: { in: 1..5 }
  validates :domain_check_id, uniqueness: { scope: :user_id, message: "already has feedback from this user" }

  scope :recent, -> { order(created_at: :desc) }
end
