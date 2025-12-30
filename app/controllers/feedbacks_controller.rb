class FeedbacksController < ApplicationController
  before_action :set_domain_check

  def create
    @feedback = @domain_check.feedbacks.build(feedback_params)
    @feedback.user = current_user

    if @feedback.save
      respond_to do |format|
        format.html { redirect_to check_path(@domain_check), notice: "Thank you for your feedback!" }
        format.turbo_stream { render turbo_stream: turbo_stream.replace("feedback_form_#{@domain_check.id}", partial: "feedbacks/thanks", locals: { domain_check: @domain_check }) }
      end
    else
      respond_to do |format|
        format.html { redirect_to check_path(@domain_check), alert: @feedback.errors.full_messages.join(", ") }
        format.turbo_stream { render turbo_stream: turbo_stream.replace("feedback_form_#{@domain_check.id}", partial: "feedbacks/form", locals: { domain_check: @domain_check, feedback: @feedback }) }
      end
    end
  end

  private

  def set_domain_check
    @domain_check = current_user.domain_checks.find(params[:check_id])
  end

  def feedback_params
    params.require(:feedback).permit(:accuracy_rating, :comments)
  end
end

