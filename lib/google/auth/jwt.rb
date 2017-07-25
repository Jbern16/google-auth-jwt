require "google/auth/jwt/version"
require 'base64'
require 'openssl'
require 'json'

module Google
  module Auth
    module Jwt
      class CreateJWT

        DEFAULT_AUD = 'https://www.googleapis.com/oauth2/v4/token'
        DEFAULT_OFFSET = 600 # 1 Hour

        def initialize (email , scope , key, sub=nil)
          @email = email
          @scope = scope
          @key   = key
          @sub   = sub
        end

        def scope
          @scope.join(" ")
        end

        def signed_jwt(audience=DEFAULT_AUD, offset=DEFAULT_OFFSET)
          claim_set_and_headers = unsigned_jwt(audience, offset)
          [claim_set_and_headers, jwt_signature(claim_set_and_headers)].join('.')
        end

        private

        def construct_claim_set(audience, offset)
          set = {
            iss: @email,
            sub: @sub,
            scope: scope,
            aud: audience,
            exp: get_time(offset),
            iat: get_time
          }
          # if an email to impersonate wasn't provided
          unless @sub
            set.delete(:sub)
          end
          
          set
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
          key         = @key
          digest      = OpenSSL::Digest::SHA256.new
          pkey        = OpenSSL::PKey::RSA.new(key)
          digest      = OpenSSL::Digest::SHA256.new
          Base64.urlsafe_encode64(pkey.sign(digest, unsigned_jwt))
        end

        def encode64(thing_to_encode)
          Base64.urlsafe_encode64(thing_to_encode.to_json.encode('UTF-8'))
        end
      end
    end
  end
end
