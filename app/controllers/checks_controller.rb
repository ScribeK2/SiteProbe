class ChecksController < ApplicationController
  def index
    @domain_checks = current_user.domain_checks.order(created_at: :desc)
  end

  def new
    @domain_check = DomainCheck.new
  end

  def create
    @domain_check = current_user.domain_checks.build(domain_check_params)

    if @domain_check.save
      # Queue the check job
      DomainCheckJob.perform_later(@domain_check.id)
      redirect_to check_path(@domain_check), notice: "Domain check started. Results will appear shortly."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def show
    @domain_check = current_user.domain_checks.find(params[:id])
  end

  private

  def domain_check_params
    params.require(:domain_check).permit(:domain, :scan_subdomains)
  end
end

