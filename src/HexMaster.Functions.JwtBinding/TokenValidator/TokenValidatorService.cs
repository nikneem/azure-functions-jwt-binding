using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using HexMaster.Functions.JwtBinding.Exceptions;
using HexMaster.Functions.JwtBinding.Model;
using HexMaster.Functions.JwtBinding.TokenValidator.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace HexMaster.Functions.JwtBinding.TokenValidator
{
    public class TokenValidatorService : ITokenValidatorService
    {
        private readonly ILogger<TokenValidatorService> _logger;
        private ICollection<SecurityKey> _securityKeys;

        public AuthorizedModel ValidateToken(
            AuthenticationHeaderValue value,
            string issuer,
            string audience,
            string signature)
        {
            if (value?.Scheme != "Bearer")
            {
                throw new AuthorizationSchemeNotSupportedException(value?.Scheme);
            }
            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new ConfigurationException("Configuring an issuer is required in order to validate a JWT Token");
            }

            var validationParameter = GetTokenValidationParameters(issuer, audience);

            if (!string.IsNullOrWhiteSpace(signature))
            {
                var sig = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(signature));
                validationParameter.IssuerSigningKey = sig;
            }
            else
            {
                var securityKeys = GetSigningKeys(issuer).Result;
                validationParameter.IssuerSigningKeys = securityKeys;
            }


            try
            {
                var handler = new JwtSecurityTokenHandler();
                var claimsPrincipal = handler.ValidateToken(value.Parameter, validationParameter, out var token);

                var displayName = GetDisplayNameFromToken(claimsPrincipal);
                return  GetAuthorizedModelFromToken(token, displayName);
            }
            catch (SecurityTokenSignatureKeyNotFoundException ex1)
            {
                _logger.LogError(ex1, "Failed to validate token signature, token is considered to be invalid");
                throw new AuthorizationFailedException(ex1);
            }
            catch (SecurityTokenException ex2)
            {
                _logger.LogError(ex2, "Failed to validate, token is considered to be invalid");
                throw new AuthorizationFailedException(ex2);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unknown exception occurred while trying to validate JWT Token");
                throw new AuthorizationFailedException(ex);
            }
        }

        private static AuthorizedModel GetAuthorizedModelFromToken(SecurityToken token, string displayName)
        {
            if (token is JwtSecurityToken jwtToken)
            {
                var nameId = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)?.Value;
                var givenName = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.GivenName)?.Value;
                return new AuthorizedModel
                {
                    Subject = jwtToken.Subject ?? nameId,
                    Name = displayName ?? givenName
                };
            }

            return null;
        }

        private static string GetDisplayNameFromToken(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal.Identity is ClaimsIdentity claimsIdentity)
            {
                return claimsIdentity.Claims.FirstOrDefault(clm => clm.Type == claimsIdentity.NameClaimType)?.Value;
            }
            return null;
        }

        private static TokenValidationParameters GetTokenValidationParameters(string issuer, string audience)
        {
            var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = false,
                ValidAudience = audience,
                ValidateAudience = !string.IsNullOrWhiteSpace(audience),
                ValidIssuer = issuer,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = false,
                ValidateLifetime = true,
            };
            return validationParameter;
        }

        private async Task<ICollection<SecurityKey>> GetSigningKeys(string issuer)
        {
            if (_securityKeys == null)
            {
                var addSlashCharacter = issuer.EndsWith("/") ? "" : "/";
                var stsDiscoveryEndpoint = $"{issuer}{addSlashCharacter}.well-known/openid-configuration";
                var retriever = new OpenIdConnectConfigurationRetriever();
                var configManager =
                    new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, retriever);

                var config = await configManager
                    .GetConfigurationAsync()
                    .ConfigureAwait(false);

                _securityKeys = config.SigningKeys;
            }

            return _securityKeys;
        }

        public TokenValidatorService(ILogger<TokenValidatorService> logger)
        {
            _logger = logger;
        }
    }
}