Gem::Specification.new do |s|
  s.name = 'acquia-http-hmac'
  s.version = '2.0.0.pre3'
  s.licenses = ['MIT']
  s.summary = "HMAC signing library and rack middleware"
  s.description = "HMAC signing library and rack middleware conforming to Acquia's HMAC 2.0 specifications"
  s.date = Time.now.strftime("%Y-%m-%d")
  s.authors = ["Peter Wolanin", "Marc Seeger"]
  s.email = 'engineering@acquia.com'
  s.homepage    = 'https://www.acquia.com/'
  s.files = Dir["[A-Z]*", "{bin,etc,lib,test}/**/*"]
  s.bindir = 'bin'
  s.require_paths = ["lib"]
  s.executables << 'acq-http-request'

  s.add_dependency('commander', '~> 4.4')
  s.add_dependency('excon', '~> 0.49')

  s.add_development_dependency('rake', '~> 10.4')
  s.add_development_dependency('grape', '~> 0.9.0')
  s.add_development_dependency('rack-test', '~> 0.6.3')
  s.add_development_dependency('multi_json', '~> 1.10')
  s.add_development_dependency('sqlite3', '~> 1.3', '>= 1.3.10')
end
