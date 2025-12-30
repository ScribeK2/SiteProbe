Rails.application.routes.draw do
  # Internal-only authentication (no registration)
  devise_for :users, skip: [:registrations]

  # Dashboard
  get "dashboard", to: "dashboard#index"
  root to: "dashboard#index"

  # Domain checks
  resources :checks, only: [:index, :new, :create, :show] do
    resource :export, only: [:show]
    resources :feedbacks, only: [:create]
  end

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check
end
