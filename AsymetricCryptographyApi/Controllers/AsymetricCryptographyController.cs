using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;

namespace AsymetricCryptographyApi.Controllers
{
    [EnableCors(origins: "*", headers: "*", methods: "*", exposedHeaders: "X-Custom-Header")]
    [RoutePrefix("key")]
    public class AsymetricCryptographyController : ApiController
    {
        [Route("generate/{mode}")]
        [HttpGet]
        public IHttpActionResult Generate([FromUri] int mode)
        {
            Dictionary<int, string> keys = null;
            AccountSecureKeyViewModel result = null;

            try
            {
                var keyPairGenerator = new RsaKeyPairGenerator();
                CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
                keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(randomGenerator), mode));
                var keyPairs = keyPairGenerator.GenerateKeyPair();
                if (keyPairs == null)
                    throw new Exception("Fail to generate asymmetric keys");

                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPairs.Private);
                byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();

                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPairs.Public);
                byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();

                keys = new Dictionary<int, string>
                {
                    { Convert.ToInt32(RSAKeyType.Private), Convert.ToBase64String(serializedPrivateBytes) },
                    { Convert.ToInt32(RSAKeyType.Public), Convert.ToBase64String(serializedPublicBytes) }
                };

                if (keys.Count > 0)
                {
                   result = new AccountSecureKeyViewModel()
                   {
                        PublicKey = keys[Convert.ToInt32(RSAKeyType.Public)],
                        PrivateKey = keys[Convert.ToInt32(RSAKeyType.Private)],
                   };
                }

                if (result == null)
                    throw new Exception("Fail to generate asymmetric keys");

                return Ok(result);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }

        }
    }

    public enum RSAKeyType
    {
        Private = 1,
        Public = 2
    }

    public class AccountSecureKeyViewModel
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }
}
