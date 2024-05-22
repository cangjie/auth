using System;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Extensions.AspNetCore;
using System.Collections.Generic;
//using JWT.Builder;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;

namespace SampleMvcApp.Controllers
{
    [ApiController]
    [Route("[controller]/[action]")]
    public class JWTController:ControllerBase
	{
		public const string plainTextSecurityKey = "test key";

        

        public JWTController()
		{
           
		}

        [HttpGet]
        public ActionResult<string> Encode(string json, int expireMinute = 0)
        {
            IDateTimeProvider provider = new UtcDateTimeProvider();
            IJsonSerializer serializer = new JsonNetSerializer();
            var payload = serializer.Deserialize<Dictionary<string, object>>(json);
            if (expireMinute > 0)
            {
                var now = provider.GetNow().AddMinutes(expireMinute);
                double secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);
                payload.Add("exp", secondsSinceEpoch);
            }
            string privateKeyStr = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd()
                .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Trim();
            byte[] privateKey = Convert.FromBase64String(privateKeyStr);
            RSA rsaPrivateKey = RSA.Create();
            //rsa.pub(publicKey, out _);
            rsaPrivateKey.ImportPkcs8PrivateKey(privateKey, out _);
            IJwtAlgorithm algorithm = new RS256Algorithm(RSA.Create(), rsaPrivateKey);
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            //byte[] keybArr = System.Text.Encoding.UTF8.GetBytes(key);
            const string key = null;
            var token = encoder.Encode(payload, key);
            return Ok(token.ToString().Trim());
        }


        [HttpGet]
        public ActionResult<string> Decode(string token)
        {
            IJsonSerializer serializer = new JsonNetSerializer();
            string privateKeyStr = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd()
                .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Trim();
            byte[] privateKey = Convert.FromBase64String(privateKeyStr);
            RSA rsaPrivateKey = RSA.Create();
            //rsa.pub(publicKey, out _);
            rsaPrivateKey.ImportPkcs8PrivateKey(privateKey, out _);
            RSA rsaPublicKey = RSA.Create();
            rsaPublicKey.ImportRSAPublicKey(rsaPrivateKey.ExportRSAPublicKey(), out _);
            IDateTimeProvider provider = new UtcDateTimeProvider();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtValidator validator = new JwtValidator(serializer, provider);
            IJwtAlgorithm algorithm = new RS256Algorithm(rsaPublicKey, rsaPrivateKey);
            IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
            var json = decoder.Decode(token);
            return Ok(json.ToString());
        }

        [NonAction]
		public void Test()
		{

            IDateTimeProvider provider = new UtcDateTimeProvider();
            var now = provider.GetNow().AddMinutes(5);
            double secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);

            //X509Certificate  cert = X509Certificate2.CreateFromCertFile(Environment.CurrentDirectory + "/certificate.crt");

            var payload = new Dictionary<string, object>
            {
                { "claim1", 0 },
                { "claim2", "claim2-value" },
                { "exp", secondsSinceEpoch}
            };

            
            //var payloadBytes = GetBytes(_jsonSerializer.Serialize(payload));

            string publicKeyStr = System.IO.File.OpenText(Environment.CurrentDirectory + "/rsa_public.key").ReadToEnd()
                .Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Trim();
            byte[] publicKey = Convert.FromBase64String(publicKeyStr);
            string privateKeyStr = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd()
                .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Trim();
            byte[] privateKey = Convert.FromBase64String(privateKeyStr);
            RSA rsaPrivateKey = RSA.Create();
            //rsa.pub(publicKey, out _);
            rsaPrivateKey.ImportPkcs8PrivateKey(privateKey, out _);
            publicKey = rsaPrivateKey.ExportRSAPublicKey();
            RSA rsaPublicKey = RSA.Create();
            rsaPublicKey.ImportRSAPublicKey(publicKey, out _);
            IJwtAlgorithm algorithm = new RS256Algorithm(rsaPublicKey, rsaPrivateKey);
            


            IJsonSerializer serializer = new JsonNetSerializer();

            //byte[] payloadBytes = System.Text.Encoding.UTF8.GetBytes(serializer.Serialize(payload));

            
            
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            //string key = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd();
            //byte[] keybArr = System.Text.Encoding.UTF8.GetBytes(key);
            const string key = null;
            //byte[] sign = algorithm.Sign(key, payloadBytes) ;
            var token = encoder.Encode(payload, key);

            Console.WriteLine(token);
            //Console.WriteLine(token);
            //IJsonSerializer serializer = new JsonNetSerializer();
            //IDateTimeProvider provider = new UtcDateTimeProvider();
            IJwtValidator validator = new JwtValidator(serializer, provider);
            //IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            
            algorithm = new RS256Algorithm(rsaPublicKey, RSA.Create());
            IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

            var json = decoder.Decode(token);
            Console.WriteLine(json);
            JwtHeader header = decoder.DecodeHeader<JwtHeader>(token);
            Console.WriteLine(header);
        }

        
    }
}

