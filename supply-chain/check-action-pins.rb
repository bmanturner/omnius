#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "json"
require "pathname"
require "psych"
require "set"

REPOSITORY = Pathname.new(__dir__).parent.freeze
WORKFLOWS = (REPOSITORY / ".github" / "workflows").freeze
ACTIONS = (REPOSITORY / ".github" / "actions").freeze
EXEMPTIONS = (Pathname.new(__dir__) / "action-pin-exemptions.json").freeze
REMOTE_SHA = %r{\A[^/@\s]+/[^@\s]+@[0-9a-fA-F]{40}\z}
IMAGE_DIGEST = %r{\A(?:docker://)?[^@\s]+@sha256:[0-9a-fA-F]{64}\z}

class ExecutableReferences
  attr_reader :references

  def initialize(path, kind)
    @path = path
    @kind = kind
    @references = []
  end

  def collect
    visit(Psych.parse_stream(@path.read), [])
    references
  rescue Psych::SyntaxError => error
    raise "invalid workflow/action YAML #{@path}: #{error.message}"
  end

  private

  def visit(node, keys)
    raise "workflow/action YAML aliases are prohibited: #{@path}" if node.is_a?(Psych::Nodes::Alias)
    raise "workflow/action YAML anchors are prohibited: #{@path}" if node.respond_to?(:anchor) && node.anchor

    case node
    when Psych::Nodes::Mapping
      visit_mapping(node, keys)
    when Psych::Nodes::Stream, Psych::Nodes::Document, Psych::Nodes::Sequence
      node.children.each { |child| visit(child, keys) }
    end
  end

  def visit_mapping(mapping, keys)
    seen = Set.new
    mapping.children.each_slice(2) do |key, value|
      raise "non-scalar workflow/action key is prohibited: #{@path}" unless key.is_a?(Psych::Nodes::Scalar)
      raise "duplicate workflow/action key #{key.value.inspect}: #{@path}" unless seen.add?(key.value)

      current = keys + [key.value]
      if reusable_workflow_path?(current)
        add_literal(value, :workflow, "uses")
      elsif action_path?(current)
        add_literal(value, :action, "uses")
      elsif container_scalar_path?(current) && value.is_a?(Psych::Nodes::Scalar)
        add_literal(value, :image, "container")
      elsif container_image_path?(current)
        add_literal(value, :image, "image")
      elsif action_metadata_image_path?(current)
        add_action_metadata_image(value)
      else
        visit(value, current)
      end
    end
  end

  def reusable_workflow_path?(keys)
    @kind == :workflow && keys.length == 3 && keys[0] == "jobs" && keys[2] == "uses"
  end

  def action_path?(keys)
    if @kind == :workflow
      keys.length == 4 && keys[0] == "jobs" && keys[2] == "steps" && keys[3] == "uses"
    else
      keys == %w[runs steps uses]
    end
  end

  def container_scalar_path?(keys)
    @kind == :workflow && keys.length == 3 && keys[0] == "jobs" && keys[2] == "container"
  end

  def container_image_path?(keys)
    return false unless @kind == :workflow && keys[0] == "jobs"

    (keys.length == 4 && keys[2..] == %w[container image]) ||
      (keys.length == 5 && keys[2] == "services" && keys[4] == "image")
  end

  def action_metadata_image_path?(keys)
    @kind == :action && keys == %w[runs image]
  end

  def add_literal(value, kind, field)
    unless value.is_a?(Psych::Nodes::Scalar) && value.anchor.nil? && value.tag.nil?
      raise "#{field} must contain one literal scalar reference: #{@path}"
    end
    references << [kind, value.value]
  end

  def add_action_metadata_image(value)
    unless value.is_a?(Psych::Nodes::Scalar) && value.anchor.nil? && value.tag.nil?
      raise "runs.image must contain one literal scalar value: #{@path}"
    end
    references << [:image, value.value] if value.value.start_with?("docker://")
  end
end

def workflow_files
  Dir.glob((WORKFLOWS / "*.{yml,yaml}").to_s).sort.map do |path|
    candidate = Pathname.new(path)
    repository_file(candidate.relative_path_from(REPOSITORY).to_s, "workflow")
  end
end

def action_files
  return [] unless ACTIONS.directory?

  Dir.glob((ACTIONS / "**" / "{action.yml,action.yaml}").to_s).sort.map do |path|
    candidate = Pathname.new(path)
    repository_file(candidate.relative_path_from(REPOSITORY).to_s, "action metadata")
  end
end

def repository_file(relative, description)
  path = (REPOSITORY / relative).cleanpath
  unless path == REPOSITORY || path.to_s.start_with?("#{REPOSITORY}/")
    raise "#{description} escapes repository: ./#{relative}"
  end
  raise "#{description} does not exist: ./#{relative}" unless path.file?
  raise "#{description} cannot be a symlink: ./#{relative}" if path.symlink?
  unless path.realpath.to_s.start_with?("#{REPOSITORY.realpath}/")
    raise "#{description} escapes repository: ./#{relative}"
  end

  path
end

def local_action(reference)
  directory = reference.delete_prefix("./")
  candidates = %w[action.yml action.yaml]
    .map { |name| (REPOSITORY / directory / name).cleanpath }
    .select(&:file?)
  raise "local action has no action.yml/action.yaml: #{reference}" if candidates.empty?
  raise "local action has ambiguous metadata files: #{reference}" if candidates.length > 1

  repository_file(candidates.first.relative_path_from(REPOSITORY).to_s, "local action metadata")
end

def local_workflow(reference)
  relative = reference.delete_prefix("./")
  unless relative.start_with?(".github/workflows/") && %w[.yml .yaml].include?(File.extname(relative))
    raise "local reusable workflow must be under .github/workflows: #{reference}"
  end

  repository_file(relative, "local reusable workflow")
end

def immutable_reference?(kind, reference)
  case kind
  when :action
    REMOTE_SHA.match?(reference) || IMAGE_DIGEST.match?(reference)
  when :workflow
    REMOTE_SHA.match?(reference)
  when :image
    IMAGE_DIGEST.match?(reference)
  else
    false
  end
end

def mutable_references
  workflows = workflow_files
  raise "no GitHub Actions workflows found" if workflows.empty?

  queue = workflows.map { |path| [path, :workflow] } + action_files.map { |path| [path, :action] }
  seen = Set.new
  mutable = Hash.new(0)
  reference_count = 0

  until queue.empty?
    path, document_kind = queue.shift
    identity = path.cleanpath.to_s
    next unless seen.add?(identity)

    relative = path.relative_path_from(REPOSITORY).to_s
    ExecutableReferences.new(path, document_kind).collect.each do |kind, reference|
      reference_count += 1
      if reference.start_with?("./")
        queue << [kind == :workflow ? local_workflow(reference) : local_action(reference), kind]
        next
      end
      next if immutable_reference?(kind, reference)

      mutable[[relative, reference]] += 1
    end
  end
  [mutable, reference_count]
end

def configured_exemptions
  document = JSON.parse(EXEMPTIONS.read)
  entries = document.fetch("exemptions")
  raise "action-pin exemptions must be an array" unless entries.is_a?(Array)

  configured = {}
  entries.each do |entry|
    raise "action-pin exemption must be an object" unless entry.is_a?(Hash)

    expected_keys = %w[expires occurrences reason reference workflow].to_set
    raise "action-pin exemption has unexpected fields" unless entry.keys.to_set == expected_keys

    workflow = entry.fetch("workflow")
    reference = entry.fetch("reference")
    occurrences = entry.fetch("occurrences")
    reason = entry.fetch("reason")
    expires = Date.iso8601(entry.fetch("expires"))
    unless workflow.is_a?(String) && workflow.start_with?(".github/workflows/")
      raise "every pin exemption needs a workflow path"
    end
    raise "invalid exempt executable reference for #{workflow}" unless reference.is_a?(String) && !reference.empty?
    unless occurrences.is_a?(Integer) && occurrences.positive?
      raise "invalid occurrence count for #{workflow}: #{reference}"
    end
    raise "missing exemption reason for #{workflow}: #{reference}" unless reason.is_a?(String) && !reason.strip.empty?
    if expires < Time.now.utc.to_date
      raise "expired pin exemption (#{expires.iso8601}): #{workflow}: #{reference}"
    end

    key = [workflow, reference]
    raise "duplicate pin exemption: #{workflow}: #{reference}" if configured.key?(key)

    configured[key] = occurrences
  end
  configured
end

def main
  actual, reference_count = mutable_references
  configured = configured_exemptions
  failures = []

  actual.sort.each do |key, count|
    expected = configured[key]
    if expected.nil?
      failures << "mutable executable reference: #{key[0]}: #{key[1]} (#{count} occurrence(s))"
    elsif count != expected
      failures << "pin exemption count changed: #{key[0]}: #{key[1]} (expected #{expected}, found #{count})"
    end
  end

  configured.sort.each do |key, expected|
    next if actual.key?(key)

    failures << "stale pin exemption: #{key[0]}: #{key[1]} (expected #{expected} occurrence(s))"
  end

  unless failures.empty?
    warn failures.join("\n")
    return 1
  end

  puts "pin policy passed: #{reference_count} executable references checked, #{actual.values.sum} bounded bootstrap exemption(s)"
  0
rescue Date::Error, JSON::ParserError, KeyError, RuntimeError, SystemCallError, TypeError => error
  warn "pin policy error: #{error.message}"
  1
end

exit(main)
