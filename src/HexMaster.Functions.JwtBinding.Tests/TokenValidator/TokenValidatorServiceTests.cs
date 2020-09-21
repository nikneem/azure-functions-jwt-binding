using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using HexMaster.Functions.JwtBinding.Exceptions;
using HexMaster.Functions.JwtBinding.TokenValidator;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;

namespace HexMaster.Functions.JwtBinding.Tests.TokenValidator
{
    [TestFixture]
    public class TokenValidatorServiceTests
    {

        private Mock<ILogger<TokenValidatorService>> _loggerMock;
        private TokenValidatorService _service;
        private string _audience;
        private string _issuer;
        private string _scheme;
        private string _token;
        private string _subject;
        private string _signature;

        [SetUp]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<TokenValidatorService>>();
            _service = new TokenValidatorService(_loggerMock.Object);
        }

        [Test]
        public void WhenTokenSchemeIsInvalid_ThenItThrowsAuthorizationSchemeNotSupportedException()
        {
            WithValidJwtToken();
            WithInvalidScheme();
            Assert.Throws<AuthorizationSchemeNotSupportedException>(Act);
        }

        private void WithInvalidScheme()
        {
            _scheme = "Invalid";
        }

        private void WithValidJwtToken()
        {
            _audience = "my-valid-audience";
            _issuer = "https://my-valid-issuer";
            _scheme = "Bearer";
            _subject = $"{DateTime.UtcNow.Ticks}";
            _signature = Guid.NewGuid().ToString();
            _token = CreateJwtToken();
        }

        private string CreateJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Create JWToken
            var token = tokenHandler.CreateJwtSecurityToken(
                _issuer, 
                _audience, 
                CreateClaimsIdentities(),
                DateTime.UtcNow,
                DateTime.UtcNow.AddDays(1),
                signingCredentials:
                new SigningCredentials(
                    new SymmetricSecurityKey(
                        Encoding.Default.GetBytes(_signature)),
                    SecurityAlgorithms.HmacSha256Signature));

            return tokenHandler.WriteToken(token);
        }

        private ClaimsIdentity CreateClaimsIdentities()
        {
            var claimsIdentity = new ClaimsIdentity();
            claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, _subject));
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, "Freddy Franeker"));

            //var roles = Enumerable.Empty<Role>(); // Not a real list.

            //foreach (var role in roles)
            //{ claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role.RoleName)); }

            return claimsIdentity;
        }


        private void Act()
        {
            _service.ValidateToken(
                new AuthenticationHeaderValue(_scheme, _token),
                _audience,
                _issuer);
        }


    }
}