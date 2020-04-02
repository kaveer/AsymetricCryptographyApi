using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
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
            KeyPairsModel result = null;

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
                   result = new KeyPairsModel()
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

        [Route("encrypt")]
        [HttpPost]
        public IHttpActionResult Encrypt([FromBody] Cryptographymodel item)
        {
            try
            {
                byte[] keyBytes = Convert.FromBase64String(item.PublicKey);

                RsaKeyParameters publicKeyInfo = (RsaKeyParameters)PublicKeyFactory.CreateKey(keyBytes);

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = publicKeyInfo.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = publicKeyInfo.Exponent.ToByteArrayUnsigned();
                rsa.ImportParameters(rsaParameters);

                byte[] bytes = Encoding.UTF8.GetBytes(item.Plaintext);
                byte[] enc = rsa.Encrypt(bytes, false);
                string base64Enc = Convert.ToBase64String(enc);


                return Ok(base64Enc);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        [Route("decrypt")]
        [HttpPost]
        public IHttpActionResult Decrypt([FromBody] Cryptographymodel item)
        {
            try
            {
                RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(item.PrivateKey));
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

                RSAParameters rsaParameters2 = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKey);

                rsa.ImportParameters(rsaParameters2);

                byte[] dec = rsa.Decrypt(Convert.FromBase64String(item.Chipertext), false);
                string decStr = Encoding.UTF8.GetString(dec);


                return Ok(decStr);
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

    public class KeyPairsModel
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }

    public class Cryptographymodel: KeyPairsModel
    {
        public string Plaintext { get; set; }
        public string Chipertext { get; set; }
    }
}
