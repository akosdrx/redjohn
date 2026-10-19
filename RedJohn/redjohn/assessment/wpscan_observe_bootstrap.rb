# frozen_string_literal: true
# RedJohn-authored offline wrapper. No WPScan source or gem activation occurs here.
# The separately provided component consists only of exact reviewed upstream ranges.
require 'json'
require 'uri'
require 'digest'
raise 'ruby_runtime_identity_mismatch' unless RUBY_ENGINE == 'ruby' && RUBY_VERSION == '3.3.12' && RUBY_PLATFORM.include?('linux')
require 'nokogiri'
require 'racc/parser'
raise 'parser_runtime_identity_mismatch' unless Nokogiri::VERSION == '1.19.4' && Racc::VERSION == '1.8.1'
raise 'native_parser_missing' unless $LOADED_FEATURES.any? { |f| f.end_with?('/nokogiri/nokogiri.so') } &&
  $LOADED_FEATURES.any? { |f| f.end_with?('/racc/cparse.so') }
FORBIDDEN_COMPONENTS = %r{/(?:ferrum|typhoeus|active_support|get_process_mem|mini_portile2|wpscan)(?:/|\.rb\z)}
# Force the same lazy parser/default-library closure for health and observation.
Digest::SHA256.hexdigest('')
URI.join('https://redjohn.invalid/', 'owned')
Nokogiri::HTML4.parse('<html></html>').css('meta[name="generator"]')

def runtime_files
  raise 'unexpected_full_platform_dependency' if $LOADED_FEATURES.any? { |feature| FORBIDDEN_COMPONENTS.match?(feature) }
  files = $LOADED_FEATURES.select { |feature| feature.start_with?('/') }.uniq.sort
  raise 'runtime_feature_budget' unless files.length <= 512 && files.all? { |feature| feature.bytesize <= 4096 }
  files
end

if ARGV == ['--health']
  puts JSON.generate({ 'schema_version' => 1,
    'runtime' => { 'ruby' => RUBY_VERSION, 'nokogiri' => Nokogiri::VERSION,
                   'racc' => Racc::VERSION, 'network' => 'offline' },
    'ruby_revision' => RUBY_REVISION.to_s, '_runtime_files' => runtime_files })
  exit 0
end
raise 'frame_arguments_invalid' unless ARGV.length == 2
# Namespace/cgroup admission belongs to the trusted supervisor, not this parser.
# This is additional output-file protection; its presence proves no OS boundary.
Process.setrlimit(Process::RLIMIT_FSIZE, 1024 * 1024, 1024 * 1024)

def regular_bytes(path, limit)
  File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
    raise 'input_not_regular_or_bounded' unless file.stat.file? && file.stat.size <= limit
    data = file.read(limit + 1)
    raise 'input_over_budget' unless data && data.bytesize <= limit
    data
  end
end

frame = JSON.parse(regular_bytes(ARGV[0], 512 * 1024), max_nesting: 8, create_additions: false)
raise 'input_schema' unless frame.is_a?(Hash) && frame.keys.sort ==
  %w[component_sha256 html html_sha256 page_url schema_version] && frame['schema_version'] == 1
html = frame['html']
raise 'html_schema' unless html.is_a?(String) && html.valid_encoding? && html.bytesize <= 256 * 1024 &&
  !html.include?("\0") && Digest::SHA256.hexdigest(html.b) == frame['html_sha256']
component = regular_bytes(ARGV[1], 4096)
COMPONENT_SHA256 = '002dae6850a08ecfe5abc1afcb694642b9d9132fd8406193d2987be6e4ecf70b'
raise 'component_identity' unless Digest::SHA256.hexdigest(component) == COMPONENT_SHA256 &&
  frame['component_sha256'] == COMPONENT_SHA256

class RedJohnWPObservation
  Response = Struct.new(:html)

  def initialize(page_url, body)
    @uri = URI.parse(page_url)
    raise 'page_url_schema' unless %w[http https].include?(@uri.scheme) && @uri.host && !@uri.userinfo && !@uri.fragment
    # Explicit NONET, no DTDLOAD/NOENT/HUGE. Only supplied HTML is parsed.
    options = Nokogiri::XML::ParseOptions::RECOVER | Nokogiri::XML::ParseOptions::NONET |
      Nokogiri::XML::ParseOptions::NOERROR | Nokogiri::XML::ParseOptions::NOWARNING
    @response = Response.new(Nokogiri::HTML4.parse(body, page_url, 'UTF-8', options))
  end

  def in_scope_uris(response, xpath)
    response.html.xpath(xpath).first(1024).each do |attribute|
      begin
        uri = URI.join(@uri.to_s, attribute.text.strip)
        next unless uri.scheme == @uri.scheme && uri.host == @uri.host && uri.port == @uri.port && !uri.userinfo
        yield uri
      rescue URI::Error, ArgumentError
        next
      end
    end
  end

  def comments_from_page(pattern, response)
    response.html.xpath('//comment()').first(1024).select { |node| pattern.match?(node.text) }
  end

  def observe
    signature = wordpress_from_meta_comments_or_scripts?(@response)
    generators = @response.html.css('meta[name="generator"]').first(16).filter_map do |node|
      value = node['content'].to_s.strip
      next unless value.length.between?(1, 128)
      match = /\AWordPress(?:\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?))?\z/i.match(value)
      next unless match
      { 'value' => value, 'version' => match[1].to_s,
        'version_status' => 'unverified_generator_observation' }
    end
    [signature, generators]
  end
end
# This path is a trusted, hash-checked, read-only snapshot prepared by the host.
# It contains one fixed detector method and three constants; never arbitrary input.
Object.class_eval(component, 'redjohn-external-wpscan-component.rb', 1)
signature, generators = RedJohnWPObservation.new(frame['page_url'], html).observe
puts JSON.generate({ 'schema_version' => 1, 'wordpress_signature' => signature,
  'generator_observations' => generators, 'html_sha256' => frame['html_sha256'],
  'component_sha256' => frame['component_sha256'],
  'runtime' => { 'ruby' => RUBY_VERSION, 'nokogiri' => Nokogiri::VERSION,
                 'racc' => Racc::VERSION, 'network' => 'offline' },
  'requests' => 0, 'coverage_status' => 'partial', '_runtime_files' => runtime_files })
