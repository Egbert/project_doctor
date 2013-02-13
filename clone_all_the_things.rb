class Import
  def prompt_and_start
    while true
      print "Are You using heroku accounts? [y/n]: "
      case gets.strip
        when 'Y', 'y', 'j', 'J', 'yes', 'ja'
          STDOUT.puts "Heroku account to use for heroku repos"
          system 'stty echo'
          account = STDIN.gets.chomp
          system 'stty echo'
          get_repos(account)
        when /\A[nN]o?\Z/ #n or no
          print "Using default heroku account"
          get_repos("com")
      end
    end
  end

  def get_repos(account="work")
    Dir.chdir './repos'
    `heroku apps`.each_line do |line|
      next if line.strip.empty?
      next if line =~ /\A===/
      app_name = line[/^[^\s]+/]
      `git clone git@heroku.#{account}:#{app_name}.git`
    end
  end
end


Import.new.prompt_and_start
exit
