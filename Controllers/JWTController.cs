using System;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using System.Collections.Generic;
//using JWT.Builder;
using System.IdentityModel.Tokens.Jwt;

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
		public void Test()
		{



            //X509Certificate  cert = X509Certificate2.CreateFromCertFile(Environment.CurrentDirectory + "/certificate.crt");

            var payload = new Dictionary<string, object>
            {
                { "claim1", 0 },
                { "claim2", "claim2-value" }
            };

            //var payloadBytes = GetBytes(_jsonSerializer.Serialize(payload));

            IJwtAlgorithm algorithm = new RS256Algorithm((new X509Certificate2(Environment.CurrentDirectory + "/cert.crt")).GetRSAPrivateKey()) ;



            IJsonSerializer serializer = new JsonNetSerializer();

            byte[] payloadBytes = System.Text.Encoding.UTF8.GetBytes(serializer.Serialize(payload));

            
            
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            //string key = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd();
            //byte[] keybArr = System.Text.Encoding.UTF8.GetBytes(key);
            const string key = null;
            //byte[] sign = algorithm.Sign(key, payloadBytes) ;
            var token = encoder.Encode(payload, key);

            Console.WriteLine(token);
            //Console.WriteLine(token);


        }

        
    }
}

