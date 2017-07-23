require "spec_helper"

RSpec.describe Google::Auth::Jwt do
  it "has a version number" do
    expect(Google::Auth::Jwt::VERSION).not_to be nil
  end

  it "creates JWT" do
    jwt = Google::Auth::Jwt::CreateJWT.new(
      email: 'jbern16@gmail.com',
      scope: ["https://www.googleapis.com/auth/adexchange.buyer"], 
      key: File.read('spec/google/auth/mock/example_creds.txt')
    )
    signed_jwt = jwt.signed_jwt
    puts signed_jwt
    expect(signed_jwt).to eq("")
  end
end
