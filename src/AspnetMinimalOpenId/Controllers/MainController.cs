using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AspnetMinimalOpenId.Controllers;

[ApiController]
public class MainController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public MainController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpGet]
    [Route("/get-token")]
    public IActionResult GetToken()
    {
        var certificate = X509Certificate2.CreateFromPem(_configuration["Certificate"], _configuration["PrivateKey"]);
        var securityKey = new X509SecurityKey(certificate);
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            //audience: "aspnet-minimal-openid",
            issuer: "https://localhost:7190/",
            //claims: new List<Claim>
            //{
            //    new Claim("foo", "bar"),
            //},
            expires: DateTime.Now.Add(TimeSpan.FromHours(1)),
            signingCredentials: signingCredentials);

        return Ok(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
    }

    [HttpGet]
    [Route("/.well-known/openid-configuration")]
    public IActionResult Configuration()
    {
        return Ok(new OpenIdConnectConfiguration
        {
            Issuer = "https://localhost:7190/",
            JwksUri = "https://localhost:7190/.well-known/openid-configuration/jwks",
        });
    }

    [HttpGet]
    [Route("/.well-known/openid-configuration/jwks")]
    public IActionResult Jwks()
    {
        var jsonWebKeySet = new JsonWebKeySet();
        var certificate = X509Certificate2.CreateFromPem(_configuration["Certificate"]);
        var rsaParameters = ((RSA)certificate.PublicKey.Key).ExportParameters(false);
        var jsonWebKey = new JsonWebKey
        {
            Kty = certificate.PublicKey.Key.KeyExchangeAlgorithm,
            Use = "sig",
            Kid = certificate.Thumbprint,
            X5t = certificate.Thumbprint,
            N = Convert.ToBase64String(rsaParameters.Modulus),
            E = Convert.ToBase64String(rsaParameters.Exponent),
        };
        jsonWebKeySet.Keys.Add(jsonWebKey);

        return Ok(jsonWebKeySet);
    }

    [HttpGet]
    [Authorize]
    [Route("/test")]
    public IActionResult Test()
    {
        return Ok();
    }
}
