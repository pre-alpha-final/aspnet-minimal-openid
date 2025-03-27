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
            TokenEndpointAuthMethodsSupported = { "private_key_jwt" },
            IdTokenSigningAlgValuesSupported = { "RS256" },
            ScopesSupported = { "openid" }
        });
    }

    [HttpGet]
    [Route("/.well-known/openid-configuration/jwks")]
    public IActionResult Jwks()
    {
        var certificate = X509Certificate2.CreateFromPem(_configuration["Certificate"]);
        var rsaParameters = certificate.GetRSAPublicKey()?.ExportParameters(false);

        // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/2254
        return Ok(new Dictionary<string, List<Dictionary<string, string>>>
        {
            {
                "keys", [
                    new()
                    {
                        { "kty", certificate.GetRSAPublicKey()?.KeyExchangeAlgorithm },
                        { "use", "sig" },
                        { "kid", certificate.Thumbprint },
                        { "x5t", certificate.Thumbprint },
                        { "n", Base64UrlEncoder.Encode(rsaParameters?.Modulus ?? []) },
                        { "e", Base64UrlEncoder.Encode(rsaParameters?.Exponent ?? []) },
                    }
                ]
            }
        });
    }

    [HttpGet]
    [Authorize]
    [Route("/test")]
    public IActionResult Test()
    {
        return Ok();
    }
}
