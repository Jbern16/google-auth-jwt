require "spec_helper"

RSpec.describe Google::Auth::Jwt do

  it "has a version number" do
    expect(Google::Auth::Jwt::VERSION).not_to be nil
  end

  it "can handle multiple scopes" do 
     jwt = Google::Auth::Jwt::CreateJWT.new(
      email: 'jbern16@gmail.com',
      scope: ["scope1", "scope2"], 
      key: File.read('spec/google/auth/mock/example_creds.txt')
    )
      expect(jwt.scope).to eq ("scope1 scope2")
  end


  it "creates JWT" do
    creds = File.read('spec/google/auth/mock/example_creds.json')
    parsed = JSON.parse(creds)
    pkey   = parsed["private_key"]
    jwt = Google::Auth::Jwt::CreateJWT.new(
      'central-park@cp-site-verifier.iam.gserviceaccount.com',
      ['https://www.googleapis.com/auth/siteverification', 'https://www.googleapis.com/auth/siteverification.verify_only'],
      pkey
    )

    signed_jwt = jwt.signed_jwt
    puts "curl -d 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=#{signed_jwt}
' https://www.googleapis.com/oauth2/v4/token".delete("\n")
    expect(signed_jwt).to be_a(String)
  end

end
