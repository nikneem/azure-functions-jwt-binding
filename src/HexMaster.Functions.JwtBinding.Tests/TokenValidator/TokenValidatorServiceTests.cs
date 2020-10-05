using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using HexMaster.Functions.JwtBinding.Configuration;
using HexMaster.Functions.JwtBinding.Exceptions;
using HexMaster.Functions.JwtBinding.Model;
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
        private string _givenName;
        private string _scopes;

        [SetUp]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<TokenValidatorService>>();
            _service = new TokenValidatorService(_loggerMock.Object);
        }

        [Test]
        public void WhenTokenWithSymmetricSignatureIsValid_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            var model = Validate();

            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenTokenSchemeIsInvalid_ThenItThrowsAuthorizationSchemeNotSupportedException()
        {
            WithValidJwtToken();
            WithInvalidScheme();
            Assert.Throws<AuthorizationSchemeNotSupportedException>(Act);
        }

        [Test]
        public void WhenTokenWithSymmetricSignatureIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidSignature();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenIssuerIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidIssuer();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenIssuerIsNull_ThenItThrowsConfigurationException()
        {
            WithValidJwtToken();
            WithEmptyIssuer();
            Assert.Throws<ConfigurationException>(Act);
        }

        [Test]
        public void WhenTokenAudienceIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidAudience();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenScopeIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidScopes();
            Assert.Throws<AuthorizationFailedException>(Act);
        }


        private void WithInvalidScheme()
        {
            _scheme = "Invalid";
        }

        private void WithInvalidSignature()
        {
            _signature = Guid.NewGuid().ToString();
        }

        private void WithInvalidIssuer()
        {
            _issuer = "https://random-issuer.com";
        }

        private void WithEmptyIssuer()
        {
            _issuer = null;
        }

        private void WithInvalidAudience()
        {
            _audience = "invalid-audience";
        }

        private void WithInvalidScopes()
        {
            _scopes = "nothing:nothing";
        }

        private void WithValidJwtToken()
        {
            _audience = "my-valid-audience";
            _issuer = "https://my-valid-issuer";
            _scheme = "Bearer";
            _subject = $"{DateTime.UtcNow.Ticks}";
            _givenName = "Tommy Token";
            _signature = Guid.NewGuid().ToString();
            _scopes = "something:create,other:list";
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
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.NameId, _subject));
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.GivenName, _givenName));

            foreach (var scope in _scopes.Split(','))
            {
                claimsIdentity.AddClaim(new Claim("scp", scope));
            }

            return claimsIdentity;
        }


        private void Act()
        {
            var config = new JwtBindingConfiguration
            {
                Signature = _signature,
                Scopes = _scopes,
                Audience = _audience,
                Issuer = _issuer
            };
            _service.ValidateToken(
                new AuthenticationHeaderValue(_scheme, _token),
                config);
        }

        private AuthorizedModel Validate()
        {
            var config = new JwtBindingConfiguration
            {
                Signature = _signature,
                Scopes = _scopes,
                Audience = _audience,
                Issuer = _issuer
            };
            return _service.ValidateToken(
                new AuthenticationHeaderValue(_scheme, _token),
                config);
        }
    }
}