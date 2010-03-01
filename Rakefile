require 'rubygems'
#Gem::manage_gems
require 'rake/gempackagetask'


spec = Gem::Specification.new do |s| 
  s.name = "libacl"
  s.version = "0.0.1"
  s.author = "Zachris Trolin"
  s.email = "zachris.trolin@gmail.com"
  s.homepage = "http://github.com/zachris/acl-ffi"
  #s.platform = Gem::Platform.new 'linux-gnu'
  s.platform  =   Gem::Platform::RUBY
  s.summary = "Linux ACL for ruby using ffi"
  s.files = FileList["lib/*rb",'test/*'].to_a
  s.require_path = "lib"
  s.autorequire = "libacl"
  #s.test_files = FileList["{test}/**/*test.rb"].to_a
  s.has_rdoc = true
  s.extra_rdoc_files = ["README"]
  s.add_dependency("ffi")
  s.add_dependency("nice-ffi")
end
                             
Rake::GemPackageTask.new(spec) do |pkg| 
  pkg.need_tar = true
end 

task :default => "pkg/#{spec.name}-#{spec.version}.gem" do
    puts "generated latest version"
end
