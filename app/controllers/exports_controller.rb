class ExportsController < ApplicationController
  def show
    @domain_check = current_user.domain_checks.find(params[:check_id])

    respond_to do |format|
      format.csv { send_csv }
      format.json { render json: export_data }
    end
  end

  private

  def send_csv
    csv_data = generate_csv
    send_data csv_data,
              filename: "#{@domain_check.domain}-report-#{@domain_check.created_at.strftime('%Y%m%d')}.csv",
              type: "text/csv"
  end

  def generate_csv
    require "csv"

    CSV.generate(headers: true) do |csv|
      # Header
      csv << ["Domain Health Report"]
      csv << ["Domain", @domain_check.domain]
      csv << ["Checked At", @domain_check.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")]
      csv << ["Status", @domain_check.status]
      csv << []

      # Issues Summary
      issues = collect_all_issues
      if issues.any?
        csv << ["ISSUES FOUND"]
        csv << ["Severity", "Title", "Message", "Recommendation"]
        issues.each do |issue|
          csv << [
            issue[:severity] || issue["severity"],
            issue[:title] || issue["title"],
            issue[:message] || issue["message"],
            issue[:recommendation] || issue["recommendation"]
          ]
        end
        csv << []
      end

      # SSL Certificate
      if @domain_check.ssl_data.present?
        ssl = @domain_check.ssl_data.with_indifferent_access
        csv << ["SSL CERTIFICATE"]
        if ssl[:success] && ssl[:certificate]
          cert = ssl[:certificate].with_indifferent_access
          csv << ["Common Name", cert[:common_name]]
          csv << ["Issuer", cert[:issuer_organization] || cert[:issuer_name]]
          csv << ["Valid From", cert[:not_before]]
          csv << ["Valid Until", cert[:not_after]]
          csv << ["Days Until Expiry", cert[:days_until_expiry]]
          csv << ["Key Size", cert[:key_size]]
          csv << ["Signature Algorithm", cert[:signature_algorithm]]
          csv << ["Self-Signed", cert[:is_self_signed] ? "Yes" : "No"]
          csv << ["TLS Protocols", (ssl[:supported_protocols] || []).join(", ")]
        else
          csv << ["Error", ssl[:error] || "SSL check failed"]
        end
        csv << []
      end

      # Security Headers
      if @domain_check.http_data.present?
        http = @domain_check.http_data.with_indifferent_access
        csv << ["SECURITY HEADERS"]
        if http[:success]
          csv << ["HTTPS Available", http[:https_response]&.dig(:success) ? "Yes" : "No"]
          csv << ["Redirects to HTTPS", http[:redirects_to_https] ? "Yes" : "No"]
          csv << ["Response Time", "#{http.dig(:https_response, :response_time_ms)}ms"]
          csv << []
          csv << ["Header", "Present", "Value"]
          http[:security_headers]&.each do |header_name, info|
            info = info.with_indifferent_access if info.is_a?(Hash)
            csv << [
              header_name,
              info[:present] ? "Yes" : "No",
              info[:value] || ""
            ]
          end
        else
          csv << ["Error", http[:error] || "HTTP check failed"]
        end
        csv << []
      end

      # WHOIS Data
      if @domain_check.whois_data.present?
        whois = @domain_check.whois_data.with_indifferent_access
        csv << ["WHOIS INFORMATION"]
        if whois[:success]
          csv << ["Registrar", whois[:registrar]]
          csv << ["Registrant", whois[:registrant]]
          csv << ["Created", whois[:creation_date]]
          csv << ["Expires", whois[:expiration_date]]
          csv << ["Updated", whois[:updated_date]]
          csv << ["Nameservers", (whois[:nameservers] || []).join(", ")]
        else
          csv << ["Error", whois[:error] || "WHOIS lookup failed"]
        end
        csv << []
      end

      # DNS Records
      if @domain_check.dns_data.present?
        dns = @domain_check.dns_data.with_indifferent_access
        csv << ["DNS RECORDS"]
        if dns[:success]
          csv << ["A Records", (dns[:a_records] || []).join(", ")]
          csv << ["AAAA Records", (dns[:aaaa_records] || []).join(", ")]
          csv << ["MX Records", (dns[:mx_records] || []).map { |m| "#{m['priority'] || m[:priority]} #{m['host'] || m[:host]}" }.join(", ")]
          csv << ["NS Records", (dns[:ns_records] || []).join(", ")]
          csv << ["CNAME Records", (dns[:cname_records] || []).join(", ")]
          csv << ["TXT Records", (dns[:txt_records] || []).length.to_s + " record(s)"]
        else
          csv << ["Error", (dns[:errors] || []).join(", ") || "DNS lookup failed"]
        end
        csv << []
      end

      # Subdomains
      if @domain_check.subdomain_data.present?
        subdomains = @domain_check.subdomain_data.with_indifferent_access
        csv << ["SUBDOMAIN SCAN"]
        if subdomains[:success] && subdomains[:found].present?
          csv << ["Subdomain", "IP Addresses", "Category"]
          subdomains[:found].each do |sub|
            csv << [
              sub[:fqdn] || sub["fqdn"],
              (sub[:a_records] || sub["a_records"] || []).join(", "),
              sub[:type] || sub["type"]
            ]
          end
        else
          csv << ["No subdomains found"]
        end
      end
    end
  end

  def export_data
    {
      domain: @domain_check.domain,
      checked_at: @domain_check.created_at.iso8601,
      status: @domain_check.status,
      issues: collect_all_issues,
      ssl: @domain_check.ssl_data,
      http: @domain_check.http_data,
      whois: @domain_check.whois_data,
      dns: @domain_check.dns_data,
      subdomains: @domain_check.subdomain_data
    }
  end

  def collect_all_issues
    issues = []

    %i[whois_data dns_data ssl_data http_data].each do |data_field|
      data = @domain_check.send(data_field)
      next unless data.present?

      data = data.with_indifferent_access
      issues.concat(data[:issues] || [])
    end

    issues.sort_by { |i| { "critical" => 0, "warning" => 1, "info" => 2 }[i[:severity] || i["severity"]] || 3 }
  end
end

