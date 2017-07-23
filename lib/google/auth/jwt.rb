require "google/auth/jwt/version"
require 'base64'
require 'openssl'
require 'json'

module Google
  module Auth
    module Jwt
      class CreateJWT

        DEFAULT_AUD = 'https://www.googleapis.com/oauth2/v4/token'
        DEFAULT_OFFSET = 60 # 1 Hour
        
        attr_reader :email, :key
        
        def initialize (email: , scope: , key:)
          @email = email
          @scope = scope
          @key   = key
        end

        def scope 
          @scope.join(" ")
        end

        def signed_jwt(audience=DEFAULT_AUD, offset=DEFAULT_OFFSET)
          resolved_unsigned_jwt = unsigned_jwt(audience, offset)
          [resolved_unsigned_jwt, jwt_signature(resolved_unsigned_jwt)].join('.')
        end
 
        private 

        def construct_claim_set(audience, offset)
          {
            iss: @email,
            scope: scope,
            aud: audience,
            exp: get_time,
            iat: get_time(offset)
          }
        end
        
        # get unix time
        def get_time(offset = 0)
          (Time.now + offset).to_i
        end

        #this is boilerplate
        def jwt_header 
          encode64({ alg: "RS256", typ: "JWT" })
        end

        def jwt_claimset(claim_set)
          encode64(claim_set)
        end

        def unsigned_jwt(audience, offset)
           claim_set = construct_claim_set(audience, offset)
          [jwt_header, jwt_claimset(claim_set)].join(".")
        end
        
        def jwt_signature(unsigned_jwt)
          pkey        = OpenSSL::PKey::RSA.new(key)
          digest      = OpenSSL::Digest::SHA256.new
          Base64.encode64(pkey.sign(digest, unsigned_jwt))
        end

        def encode64(thing_to_encode)
          Base64.encode64(thing_to_encode.to_json)
        end
      end
    end
  end
end
