using PostQuantumLab.API.Authorization.Enums;
using PostQuantumLab.API.Authorization.Model;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace PostQuantumLab.Tests
{
    public class EncryptionTests
    {
        [Fact]
        public void StringToPrivateKeyTest()
        {
            var random = new SecureRandom();
            var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
            var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
            dilithiumKeyPairGenerator.Init(keyGenParameters);
            var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
            var publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
            var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
            var pubEncoded = publicKey.GetEncoded();
            var privateEncoded = privateKey.GetEncoded();

            var newPk = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium3,
                privateEncoded[0..32],
                privateEncoded[32..64],
                privateEncoded[64..96],
                privateEncoded[96..736],
                privateEncoded[736..1504],
                privateEncoded[1504..4000],
                privateEncoded[4000..]);

            Assert.Equal(privateKey.GetEncoded(), newPk.GetEncoded());
        }


        [Fact]
        public void JwtTokenSignatureTest()
        {
            var random = new SecureRandom();
            var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
            var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
            dilithiumKeyPairGenerator.Init(keyGenParameters);
            var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
            var publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
            var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;

            var pubEncoded = publicKey.GetEncoded();
            var privateEncoded = privateKey.GetEncoded();

            var privateSigner = new DilithiumSigner();
            privateSigner.Init(true, privateKey);
            var publicSigner = new DilithiumSigner();
            publicSigner.Init(false, publicKey);

            var token = new JwtToken()
            {
                alg = Algorithms.Dilithium3,
                typ = "JWT",
                sub = Guid.NewGuid().ToString()
            };


            var testSignature = privateSigner.GenerateSignature(System.Text.Encoding.UTF8.GetBytes(token.GetTokenHeader() + "." + token.GetTokenBody()));
            Assert.True(publicSigner.VerifySignature(System.Text.Encoding.UTF8.GetBytes(token.GetTokenHeader() + "." + token.GetTokenBody()), testSignature));
            var signedToken = token.GetTokenSignatureBytes(Convert.ToBase64String(privateKey.GetEncoded()));
            Assert.Equal(testSignature, signedToken);

            // Sign token with private key
            token.SignToken(Convert.ToBase64String(privateKey.GetEncoded()));

            //Test deserialization
            var deserializedToken = new JwtToken(token.ToString());

            //Verify signature with public key
            Assert.True(deserializedToken.VerifySignature(Convert.ToBase64String(pubEncoded)));
        }

        [Fact]
        public void JwtTokenToString()
        {
            var testToken = new JwtToken("c8688cdc-e4f4-447a-b156-7e8ccd402ce8", "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");
            var testString = testToken.ToString();
            Assert.Equal("eyJhbGciOiJEaWxpdGhpdW0zIiwidHlwIjoiSldUIn0=.eyJzdWIiOiJjODY4OGNkYy1lNGY0LTQ0N2EtYjE1Ni03ZThjY2Q0MDJjZTgifQ==.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", testString);
        }
    }
}
