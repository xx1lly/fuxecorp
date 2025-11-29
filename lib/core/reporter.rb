require 'json'
require 'csv'
require 'fileutils'

class Reporter
  def initialize
    @results = []
  end

  def add_result(type, data)
    @results << {
      timestamp: Time.now.to_s,
      type: type,
      data: data
    }
  end

  def export_json(filename)
    data = {
      timestamp: Time.now.to_s,
      results: @results
    }
    File.write(filename, JSON.pretty_generate(data))
    filename
  end

  def export_csv(filename)
    CSV.open(filename, "w") do |csv|
      csv << ["Timestamp", "Type", "Data"]
      @results.each do |result|
        csv << [result[:timestamp], result[:type], result[:data].to_s]
      end
    end
    filename
  end

  def export_markdown(filename, title = "Pentest Report")
    content = "# #{title}\n\n"
    content += "Generated: #{Time.now}\n\n"
    content += "## Results\n\n"
    
    @results.each do |result|
      content += "### #{result[:type]}\n\n"
      content += "**Timestamp:** #{result[:timestamp]}\n\n"
      content += "**Data:**\n```\n#{result[:data]}\n```\n\n"
    end
    
    File.write(filename, content)
    filename
  end

  def view_results
    @results
  end

  def clear
    @results = []
  end
end

