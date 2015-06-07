require 'openssl'
require 'base64'
require 'sqlite3'

module Acquia
  module HTTPHmac

    class SQLite3PasswordStorage

      def initialize(filename)
        @filename = filename
        @creds = {}
      end

      def valid?(id)
        load(id)
        !!(@creds[id] && @creds[id]['password'])
      end

      # Fetch the password using the id and timestamp from the request.
      #
      # @param [String] id
      #   An arbitrary identifier.
      # @param [Integer] timestamp
      #   A unix timestamp. The returned password may be different based on
      #   the current date or time.
      def password(id, timestamp)
        fail('Invalid id') unless valid?(id)
        load(id, timestamp.to_i)
        @creds[id]['password']
      end

      def data(id)
        fail('Invalid id') unless valid?(id)
        result = []
        connection.execute('SELECT * FROM password_data WHERE id = ?', [today]) do |row|
          result << row
        end
        result
      end

      def ids
        result = []
        connection.execute('SELECT id FROM passwords WHERE request_date = ?', [today]) do |row|
          result << row['id']
        end
        result
      end

      private

      def load(id, timestamp = nil)
        date = timestamp ? Time.at(timestamp).utc.strftime('%F') : today
        if @creds[id].nil? || date != today
          @creds[id] = false
          connection.execute('SELECT base64_password FROM passwords WHERE id = ? AND request_date = ?', [id, date]) do |row|
            @creds[id] = {}
            @creds[id]['password'] = row['base64_password']
          end
        end
      end

      def connection
        @connection ||= SQLite3::Database.new(@filename,  { readonly: true, results_as_hash: true })
      end

      def today
        @today ||= Time.now.utc.strftime('%F')
      end
    end
  end
end

