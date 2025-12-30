require "net/http"
require "uri"

class HttpChecker
  TIMEOUT = 10.seconds
  MAX_REDIRECTS = 5

  # Issue severity levels
  SEVERITY_CRITICAL = "critical"
  SEVERITY_WARNING = "warning"
  SEVERITY_INFO = "info"

  # Security headers to check
  SECURITY_HEADERS = {
    "Strict-Transport-Security" => {
      name: "HSTS",
      description: "HTTP Strict Transport Security",
      required: true,
      severity: SEVERITY_WARNING
    },
    "Content-Security-Policy" => {
      name: "CSP",
      description: "Content Security Policy",
      required: false,
      severity: SEVERITY_INFO
    },
    "X-Frame-Options" => {
      name: "X-Frame-Options",
      description: "Clickjacking protection",
      required: true,
      severity: SEVERITY_WARNING
    },
    "X-Content-Type-Options" => {
      name: "X-Content-Type-Options",
      description: "MIME type sniffing protection",
      required: true,
      severity: SEVERITY_WARNING
    },
    "X-XSS-Protection" => {
      name: "X-XSS-Protection",
      description: "XSS filter (legacy)",
      required: false,
      severity: SEVERITY_INFO
    },
    "Referrer-Policy" => {
      name: "Referrer-Policy",
      description: "Referrer information control",
      required: false,
      severity: SEVERITY_INFO
    },
    "Permissions-Policy" => {
      name: "Permissions-Policy",
      description: "Feature permissions control",
      required: false,
      severity: SEVERITY_INFO
    },
    "Cross-Origin-Opener-Policy" => {
      name: "COOP",
      description: "Cross-origin isolation",
      required: false,
      severity: SEVERITY_INFO
    },
    "Cross-Origin-Resource-Policy" => {
      name: "CORP",
      description: "Cross-origin resource sharing policy",
      required: false,
      severity: SEVERITY_INFO
    },
    "Cross-Origin-Embedder-Policy" => {
      name: "COEP",
      description: "Cross-origin embedder policy",
      required: false,
      severity: SEVERITY_INFO
    }
  }.freeze

  def self.check(domain)
    new(domain).check
  end

  def initialize(domain)
    @domain = domain.to_s.strip.downcase
  end

  def check
    cache_key = "http:#{@domain}"
    cached_result = Rails.cache.read(cache_key)
    return cached_result if cached_result

    result = {
      success: false,
      domain: @domain,
      http_response: nil,
      https_response: nil,
      redirects_to_https: false,
      security_headers: {},
      missing_headers: [],
      server_info: nil,
      issues: [],
      checked_at: Time.current.iso8601
    }

    begin
      # Check HTTP (port 80) - does it redirect to HTTPS?
      result[:http_response] = check_url("http://#{@domain}")

      # Check HTTPS (port 443)
      result[:https_response] = check_url("https://#{@domain}")

      if result[:https_response][:success]
        result[:success] = true

        # Analyze security headers
        headers = result[:https_response][:headers] || {}
        result[:security_headers] = analyze_security_headers(headers)
        result[:missing_headers] = find_missing_headers(headers)
        result[:server_info] = extract_server_info(headers)

        # Check if HTTP redirects to HTTPS
        if result[:http_response][:success]
          result[:redirects_to_https] = check_https_redirect(result[:http_response])
        end
      end

      # Detect issues
      result[:issues] = detect_issues(result)
    rescue StandardError => e
      result[:error] = "Unexpected error: #{e.message}"
    end

    # Cache successful results for 1 hour
    Rails.cache.write(cache_key, result, expires_in: 1.hour) if result[:success]

    result
  end

  private

  def check_url(url, redirect_count = 0)
    response_data = {
      url: url,
      success: false,
      status_code: nil,
      status_message: nil,
      headers: {},
      redirect_chain: [],
      final_url: url,
      response_time_ms: nil,
      error: nil
    }

    return response_data if redirect_count >= MAX_REDIRECTS

    begin
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
      http.open_timeout = TIMEOUT
      http.read_timeout = TIMEOUT

      start_time = Time.now
      response = http.request(Net::HTTP::Get.new(uri.request_uri))
      response_data[:response_time_ms] = ((Time.now - start_time) * 1000).round

      response_data[:status_code] = response.code.to_i
      response_data[:status_message] = response.message
      response_data[:headers] = response.to_hash.transform_values(&:first)
      response_data[:success] = true

      # Follow redirects
      if response.is_a?(Net::HTTPRedirection) && response["location"]
        redirect_url = resolve_redirect_url(url, response["location"])
        response_data[:redirect_chain] << {
          from: url,
          to: redirect_url,
          status: response.code.to_i
        }

        redirect_response = check_url(redirect_url, redirect_count + 1)
        response_data[:redirect_chain].concat(redirect_response[:redirect_chain] || [])
        response_data[:final_url] = redirect_response[:final_url]

        # Merge headers from final destination
        if redirect_response[:success]
          response_data[:headers] = redirect_response[:headers]
        end
      end
    rescue OpenSSL::SSL::SSLError => e
      response_data[:error] = "SSL error: #{e.message}"
    rescue Errno::ECONNREFUSED
      response_data[:error] = "Connection refused"
    rescue Errno::ETIMEDOUT, Net::OpenTimeout, Net::ReadTimeout
      response_data[:error] = "Connection timed out"
    rescue SocketError => e
      response_data[:error] = "DNS resolution failed: #{e.message}"
    rescue StandardError => e
      response_data[:error] = "Error: #{e.message}"
    end

    response_data
  end

  def resolve_redirect_url(base_url, location)
    if location.start_with?("http://", "https://")
      location
    elsif location.start_with?("/")
      uri = URI.parse(base_url)
      "#{uri.scheme}://#{uri.host}#{location}"
    else
      uri = URI.parse(base_url)
      "#{uri.scheme}://#{uri.host}/#{location}"
    end
  end

  def analyze_security_headers(headers)
    analysis = {}

    SECURITY_HEADERS.each do |header_name, config|
      header_key = headers.keys.find { |k| k.downcase == header_name.downcase }
      value = header_key ? headers[header_key] : nil

      analysis[header_name] = {
        present: value.present?,
        value: value,
        name: config[:name],
        description: config[:description],
        analysis: value ? analyze_header_value(header_name, value) : nil
      }
    end

    analysis
  end

  def analyze_header_value(header_name, value)
    case header_name
    when "Strict-Transport-Security"
      analyze_hsts(value)
    when "Content-Security-Policy"
      analyze_csp(value)
    when "X-Frame-Options"
      analyze_x_frame_options(value)
    when "X-Content-Type-Options"
      analyze_x_content_type_options(value)
    when "Referrer-Policy"
      analyze_referrer_policy(value)
    else
      { raw: value }
    end
  end

  def analyze_hsts(value)
    result = { raw: value, max_age: nil, include_subdomains: false, preload: false }

    if match = value.match(/max-age=(\d+)/i)
      result[:max_age] = match[1].to_i
      result[:max_age_days] = (result[:max_age] / 86400.0).round(1)
    end

    result[:include_subdomains] = value.downcase.include?("includesubdomains")
    result[:preload] = value.downcase.include?("preload")
    result[:strength] = calculate_hsts_strength(result)

    result
  end

  def calculate_hsts_strength(hsts)
    return "weak" if hsts[:max_age].nil? || hsts[:max_age] < 86400
    return "moderate" if hsts[:max_age] < 31536000
    return "strong" if hsts[:include_subdomains] && hsts[:preload]
    "good"
  end

  def analyze_csp(value)
    directives = {}
    value.split(";").each do |directive|
      parts = directive.strip.split(/\s+/)
      next if parts.empty?
      directives[parts[0]] = parts[1..].join(" ")
    end

    {
      raw: value,
      directives: directives,
      has_default_src: directives.key?("default-src"),
      has_script_src: directives.key?("script-src"),
      uses_unsafe_inline: value.include?("'unsafe-inline'"),
      uses_unsafe_eval: value.include?("'unsafe-eval'")
    }
  end

  def analyze_x_frame_options(value)
    normalized = value.upcase.strip
    {
      raw: value,
      mode: normalized,
      secure: %w[DENY SAMEORIGIN].include?(normalized)
    }
  end

  def analyze_x_content_type_options(value)
    {
      raw: value,
      nosniff: value.downcase.include?("nosniff")
    }
  end

  def analyze_referrer_policy(value)
    policies = value.split(",").map(&:strip)
    {
      raw: value,
      policies: policies,
      restrictive: policies.any? { |p| %w[no-referrer same-origin strict-origin strict-origin-when-cross-origin].include?(p) }
    }
  end

  def find_missing_headers(headers)
    missing = []

    SECURITY_HEADERS.each do |header_name, config|
      next unless config[:required]

      header_key = headers.keys.find { |k| k.downcase == header_name.downcase }
      unless header_key
        missing << {
          header: header_name,
          name: config[:name],
          description: config[:description],
          severity: config[:severity]
        }
      end
    end

    missing
  end

  def extract_server_info(headers)
    {
      server: headers["server"],
      powered_by: headers["x-powered-by"],
      content_type: headers["content-type"],
      cache_control: headers["cache-control"]
    }
  end

  def check_https_redirect(http_response)
    return false unless http_response[:success]

    # Check if any redirect in the chain goes to HTTPS
    http_response[:redirect_chain]&.any? do |redirect|
      redirect[:to]&.start_with?("https://")
    end || http_response[:final_url]&.start_with?("https://")
  end

  def detect_issues(result)
    issues = []

    # Check HTTPS availability
    unless result[:https_response]&.dig(:success)
      issues << {
        severity: SEVERITY_CRITICAL,
        code: "no_https",
        title: "HTTPS Not Available",
        message: "The site is not accessible over HTTPS.",
        recommendation: "Install an SSL certificate and enable HTTPS."
      }
      return issues
    end

    # Check HTTP to HTTPS redirect
    if result[:http_response]&.dig(:success) && !result[:redirects_to_https]
      issues << {
        severity: SEVERITY_WARNING,
        code: "no_https_redirect",
        title: "No HTTPS Redirect",
        message: "HTTP requests are not redirected to HTTPS.",
        recommendation: "Configure HTTP to redirect to HTTPS for all requests."
      }
    end

    # Check missing security headers
    result[:missing_headers]&.each do |header|
      issues << {
        severity: header[:severity],
        code: "missing_#{header[:header].downcase.gsub('-', '_')}",
        title: "Missing #{header[:name]}",
        message: "#{header[:description]} header is not set.",
        recommendation: "Add the #{header[:header]} header to improve security."
      }
    end

    # Check HSTS configuration
    hsts = result.dig(:security_headers, "Strict-Transport-Security")
    if hsts&.dig(:present)
      analysis = hsts[:analysis]
      if analysis[:max_age] && analysis[:max_age] < 31536000
        issues << {
          severity: SEVERITY_INFO,
          code: "hsts_short_max_age",
          title: "HSTS Max-Age Too Short",
          message: "HSTS max-age is #{analysis[:max_age_days]} days. Recommended: at least 1 year.",
          recommendation: "Set max-age to at least 31536000 (1 year)."
        }
      end
      unless analysis[:include_subdomains]
        issues << {
          severity: SEVERITY_INFO,
          code: "hsts_no_subdomains",
          title: "HSTS Missing includeSubDomains",
          message: "HSTS does not include subdomains.",
          recommendation: "Add includeSubDomains directive for comprehensive protection."
        }
      end
    end

    # Check CSP configuration
    csp = result.dig(:security_headers, "Content-Security-Policy")
    if csp&.dig(:present)
      analysis = csp[:analysis]
      if analysis[:uses_unsafe_inline]
        issues << {
          severity: SEVERITY_WARNING,
          code: "csp_unsafe_inline",
          title: "CSP Uses unsafe-inline",
          message: "Content Security Policy allows inline scripts, reducing XSS protection.",
          recommendation: "Consider using nonces or hashes instead of 'unsafe-inline'."
        }
      end
      if analysis[:uses_unsafe_eval]
        issues << {
          severity: SEVERITY_WARNING,
          code: "csp_unsafe_eval",
          title: "CSP Uses unsafe-eval",
          message: "Content Security Policy allows eval(), which can be exploited.",
          recommendation: "Remove 'unsafe-eval' if possible."
        }
      end
    end

    # Check for server information disclosure
    server_info = result[:server_info]
    if server_info[:server].present? && server_info[:server].match?(/\d+\.\d+/)
      issues << {
        severity: SEVERITY_INFO,
        code: "server_version_disclosed",
        title: "Server Version Disclosed",
        message: "Server header reveals version information: #{server_info[:server]}",
        recommendation: "Consider hiding server version information."
      }
    end

    if server_info[:powered_by].present?
      issues << {
        severity: SEVERITY_INFO,
        code: "powered_by_disclosed",
        title: "Technology Stack Disclosed",
        message: "X-Powered-By header reveals: #{server_info[:powered_by]}",
        recommendation: "Consider removing the X-Powered-By header."
      }
    end

    # Check response time
    response_time = result.dig(:https_response, :response_time_ms)
    if response_time && response_time > 3000
      issues << {
        severity: SEVERITY_WARNING,
        code: "slow_response",
        title: "Slow Response Time",
        message: "Server response time is #{response_time}ms.",
        recommendation: "Investigate server performance issues."
      }
    end

    issues
  end
end

