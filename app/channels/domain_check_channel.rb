class DomainCheckChannel < SolidCable::Channel
  def subscribed
    @domain_check = DomainCheck.find(params[:id])
    stream_from "domain_check_#{@domain_check.id}"
  end
end

