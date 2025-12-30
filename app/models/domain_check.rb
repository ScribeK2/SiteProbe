class DomainCheck < ApplicationRecord
  belongs_to :user
  has_many :feedbacks, dependent: :destroy

  enum :status, {
    pending: "pending",
    processing: "processing",
    completed: "completed",
    failed: "failed"
  }

  validates :domain, presence: true, format: { 
    with: /\A([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\z/i, 
    message: "must be a valid domain name" 
  }
end
