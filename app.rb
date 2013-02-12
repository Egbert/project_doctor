require 'rubygems'
require 'sinatra/reloader'
require 'slim'

class Defects
  def self.all
    (constants - [:AbstractDefect]).map do |constant|
      const_get constant
    end
  end

  class AbstractDefect

    def self.diagnose(repo)
      in_dir(repo) { diagnosis }
    end

    def self.check_recovery(repo)
      in_dir(repo) { diagnosis && recovery }
    end

    def self.in_dir(repo)
      Dir.chdir repo.path
      result = yield
      Dir.chdir File.dirname(__FILE__)
      result
    end

    def self.recovery
      !diagnosis
    end

    def self.gem_version(gem)
      Gem::Version.new `grep -E '^    #{gem}' Gemfile.lock`[/(\d+\.?)+/]
    end
  end

  class CVE20130276 < AbstractDefect

    def self.diagnosis
      !`Ack "attr_protected :" app/models/`.empty?
    end

    def self.recovery
      !`grep "rails (3.2.12)" Gemfile.lock`.empty?
    end

  end

  class CVE20130269 < AbstractDefect

    @@json15_max = Gem::Version.new("1.5.4")
    @@json15_min = Gem::Version.new("1.5.0")
    @@json16_max = Gem::Version.new("1.6.7")
    @@json16_min = Gem::Version.new("1.6.0")
    @@json17_max = Gem::Version.new("1.7.6")
    @@json17_min = Gem::Version.new("1.7.0")

    def self.diagnosis
      wrong_json_version && using_mysql
    end

    def self.wrong_json_version
      json_version = gem_version 'json'
      json_version &&
          (json_version <= @@json15_max ||
           json_version >= @@json16_min && json_version <= @@json16_max ||
           json_version >= @@json17_min && json_version <= @@json17_max)

    end

    def self.using_mysql
      !`grep mysql config/database.yml`.empty?
    end
  end

  class CVE20130333 < AbstractDefect

    @@rails3_max  = Gem::Version.new("3.0.19")
    @@rails3_min  = Gem::Version.new("3.0.0")
    @@rails2_max  = Gem::Version.new("2.3.15")
    @@rails2_min  = Gem::Version.new("2.3.0")

    def self.diagnosis
      rails_version = gem_version 'rails'
      rails_version &&
        (rails_version > @@rails3_min && rails_version <= @@rails3_max ||
         rails_version > @@rails2_min && rails_version <= @@rails2_max)
    end
  end

  class CVE20130156 < AbstractDefect

    @@rails32_max  = Gem::Version.new("3.2.10")
    @@rails32_min  = Gem::Version.new("3.2.0")
    @@rails31_max  = Gem::Version.new("3.1.9")
    @@rails31_min  = Gem::Version.new("3.1.0")
    @@rails30_max  = Gem::Version.new("3.0.18")
    @@rails30_min  = Gem::Version.new("3.0.0")
    @@rails2_max  = Gem::Version.new("2.3.14")
    @@rails2_min  = Gem::Version.new("2.3.0")

    def self.recovery
      !`Ack "ActionDispatch::ParamsParser::DEFAULT_PARSERS.delete\\(Mime::XML\\)" config/initializers/`.empty?
    end

    def self.diagnosis
      rails_version = gem_version 'rails'
      rails_version &&
        (rails_version > @@rails32_min && rails_version <= @@rails32_max ||
         rails_version > @@rails31_min && rails_version <= @@rails31_max ||
         rails_version > @@rails30_min && rails_version <= @@rails30_max ||
         rails_version > @@rails2_min && rails_version <= @@rails2_max)
    end

  end

end

class Repo
  attr_reader :name
  def self.all
     Dir.glob("./repos/*").map { |path| new name: File.basename(path) }
  end

  def initialize(options)
    @name = options[:name]
  end

  def path
    "./repos/#{name}"
  end

  def defects
    Defects.all.select do |defect|
      defect.diagnose self
    end
  end

  def cured_defects
    Defects.all.select do |defect|
      defect.check_recovery self
    end
  end
end

class App < Sinatra::Base
  get '/' do
    @repos = Repo.all
    slim :index
  end
end
