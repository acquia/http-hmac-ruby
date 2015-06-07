require 'sqlite3'
require 'base64'
require 'openssl'
require 'yaml'


class ExampleSQLite3Setup

  def initialize(dbfile, passwords_file)
    @dbfile = dbfile
    File.unlink(@dbfile) if File.exist?(@dbfile)
    @passwords_file = passwords_file
  end

  def create_t1
    return <<-SQL
      CREATE TABLE passwords (
        id VARCHAR(50),
        request_date CHAR(10),
        base64_password VARCHAR(255),
        PRIMARY KEY(id, request_date)
      );
    SQL
  end

  def create_t2
    return <<-SQL
      CREATE TABLE password_data (
        id VARCHAR(50),
        request_method VARCHAR(10),
        allowed_path VARCHAR(255)
      );
      CREATE INDEX pass_id ON password_data(id);
    SQL
  end

  def write_database
    db = SQLite3::Database.new(@dbfile)

    db.execute_batch(create_t1)
    db.execute_batch(create_t2)

    # Build entries for today and tomorrow
    today = Time.now.utc
    tomorrow = today + (24 * 60 * 60)

    dates =  [
      today.strftime('%F'),
      tomorrow.strftime('%F'),
    ]
    realm = 'Test'

    creds = YAML.safe_load(File.read(@passwords_file))
    passwords = {}
    creds.each do |id,data|
      passwords[id] = data['password']
    end

    data = {
      'testadmin' => [
        ['GET', '/'],
        ['POST', '/'],
      ],
      'testuser' => [],
      'curltest' => [
        ['GET', '/'],
      ],
    }

    sha256 = OpenSSL::Digest::SHA256.new

    passwords.each do |id,pass|
      # Run a 2-step HMAC KDF using date and realm
      binary_pass = Base64.decode64(pass)
      dates.each do |date|
        derived_pass1 = OpenSSL::HMAC.digest(sha256, binary_pass, date)
        derived_pass2 = OpenSSL::HMAC.digest(sha256, derived_pass1, realm)
        db.execute("INSERT INTO passwords (id, request_date, base64_password) VALUES ( ?, ?, ? )", [id, date, Base64.strict_encode64(derived_pass2)])
      end
    end

    data.each do |id, values|
      values.each do |row|
         row.unshift(id)
         db.execute("INSERT INTO password_data VALUES ( ?, ?, ? )", row)
      end
    end

    db.close
  end
end

if $0 == __FILE__

  mypath = File.dirname(__FILE__)
  dbfile = File.join(mypath, 'passwords.sqlite3')
  # Use "raw" passwords from YAML and created derived passwords
  filename = File.join(File.dirname(__FILE__), '/../fixtures/passwords.yml')

  s = ExampleSQLite3Setup.new(dbfile, filename)
  s.write_database
end
