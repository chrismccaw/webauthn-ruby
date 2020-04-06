# frozen_string_literal: true

require "spec_helper"

require "cose/algorithm"
require "openssl"
require "webauthn/relying_party"
require "webauthn/signature_verifier"

RSpec.describe "SignatureVerifier" do
  let(:signature) { key.sign(hash_algorithm, to_be_signed) }
  let(:to_be_signed) { "data" }
  let(:hash_algorithm) { COSE::Algorithm.find(algorithm_id).hash_function }
  let(:rp) { WebAuthn::RelyingParty.new }
  let(:supported_algorithms) { rp.algorithms }
  let(:verifier) { WebAuthn::SignatureVerifier.new(algorithm_id, supported_algorithms, public_key) }

  context "ES256" do
    let(:algorithm_id) { -7 }

    let(:public_key) do
      pkey = OpenSSL::PKey::EC.new("prime256v1")
      pkey.public_key = key.public_key

      pkey
    end

    let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an RSA context" do
      let(:public_key) { key.public_key }
      let(:key) { create_rsa_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { OpenSSL::PKey::EC.new("prime256v1").generate_key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "because it was signed over different data" do
      let(:signature) { key.sign(hash_algorithm, "different data") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "PS256" do
    before do
      unless OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
        skip "Ruby OpenSSL gem #{OpenSSL::VERSION} do not support RSASSA-PSS"
      end
    end

    let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm) }
    let(:algorithm_id) { -37 }
    let(:public_key) { key.public_key }
    let(:key) { create_rsa_key }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when the masking generation function was using a different hash algorithm" do
      let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: "SHA1") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) do
        create_rsa_key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm)
      end

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it was signed with the same key but using PKCS1-v1_5 padding" do
      let(:signature) { key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "RS256" do
    let(:algorithm_id) { -257 }
    let(:public_key) { key.public_key }
    let(:key) { create_rsa_key }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { create_rsa_key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it was signed with the same key but using PSS" do
      before do
        unless OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
          skip "Ruby OpenSSL gem #{OpenSSL::VERSION} do not support RSASSA-PSS"
        end
      end

      let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "RS1" do
    let(:algorithm_id) { -65535 }
    let(:public_key) { key.public_key }
    let(:key) { create_rsa_key }
    let(:supported_algorithms) { rp.algorithms + ["RS1"] }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA512" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { create_rsa_key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "because it was signed over different data" do
      let(:signature) { key.sign(hash_algorithm, "different data") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "when algorithm is unsupported" do
    let(:algorithm_id) { -260 }
    let(:hash_algorithm) { "SHA256" }

    let(:public_key) do
      pkey = OpenSSL::PKey::EC.new("prime256v1")
      pkey.public_key = key.public_key

      pkey
    end

    let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    it "fails" do
      expect {
        verifier.verify(signature, to_be_signed)
      }.to raise_error(WebAuthn::SignatureVerifier::UnsupportedAlgorithm, "Unsupported algorithm -260")
    end
  end
end
