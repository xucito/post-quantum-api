

using MimeKit;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace PostQuantum.API.Authorization
{
    public class JwtToken
    {
        public string alg { get; set; } = "Dilithium3";
        public string typ { get; set; } = "JWT";
        public string sub { get; set; } = "";
        public string sig { get; set; } = "";

        public JwtToken(string sub, string privateKey)
        {
            alg = alg;
            typ = typ;
            this.sub = sub;
            SignToken(privateKey);
        }

        public JwtToken()
        {
        }

        public JwtToken(string token)
        {
            var tokenSections = token.Split('.');
            var header = JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(tokenSections[0])));
            alg = header["alg"].ToString();
            typ = header["typ"].ToString();
            var body = JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(tokenSections[1])));
            sub = body["sub"].ToString();
            sig = tokenSections[2];
        }

        public string GetTokenHeader()
        {
            string header = JsonSerializer.Serialize(new
            {
                alg,
                typ
            });

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(header));
        }

        public string GetTokenBody()
        {
            string body = JsonSerializer.Serialize(new
            {
                sub,
            });

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(body));
        }

        public byte[] GetTokenSignatureBytes(string privateString)
        {
            var key = Convert.FromBase64String(privateString);
            var newPk = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium3,
                key[0..32],
                key[32..64],
                key[64..96],
                key[96..736],
                key[736..1504],
                key[1504..4000],
                key[4000..]);
            var signer = new DilithiumSigner();
            signer.Init(true, newPk);

            var firstTokenSection = GetTokenHeader() + "." + GetTokenBody();
            return signer.GenerateSignature(Encoding.UTF8.GetBytes(firstTokenSection));
        }

        public string GetTokenSignature(string privateString)
        {
            return Convert.ToBase64String(GetTokenSignatureBytes(privateString));
        }

        public void SignToken(string privateString)
        {
            sig = GetTokenSignature(privateString);
        }

        public bool VerifySignature(string publicKey)
        {
            var newPk = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium3, Convert.FromBase64String(publicKey));
            var publicSigner = new DilithiumSigner();
            publicSigner.Init(false, newPk);
            return publicSigner.VerifySignature(Encoding.UTF8.GetBytes(GetTokenHeader() + "." + GetTokenBody()), Convert.FromBase64String(sig));
        }

        public override string ToString()
        {
            return GetTokenHeader() + "." + GetTokenBody() + "." + sig;
        }
    }
}
