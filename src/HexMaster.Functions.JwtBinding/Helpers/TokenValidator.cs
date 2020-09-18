using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using HexMaster.Functions.JwtBinding.Model;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace HexMaster.Functions.JwtBinding.Helpers
{
    public static class TokenValidator
    {

        private static ICollection<SecurityKey> _securityKeys;

        public static AuthorizedModel ValidateToken(
            AuthenticationHeaderValue value,
            string audience,
            string issuer)
        {
            var authorizedModel = new AuthorizedModel();
            if (value?.Scheme != "Bearer")
                return null;


            var securityKeys = GetSigningKeys(issuer).Result;
            var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = false,
                ValidAudience = audience,
                ValidateAudience = !string.IsNullOrWhiteSpace(audience),
                ValidIssuer = issuer,
                ValidateIssuer = !string.IsNullOrWhiteSpace(issuer),
                ValidateIssuerSigningKey = false,
                ValidateLifetime = true,
                IssuerSigningKeys = securityKeys
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(value.Parameter, validationParameter, out var token);
                var jwtToken = token as JwtSecurityToken;
                authorizedModel.IsAuthorized = true;
                authorizedModel.Subject = jwtToken.Subject;
                authorizedModel.Name = jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;

            }
            catch (SecurityTokenSignatureKeyNotFoundException ex1)
            {
                Console.WriteLine(ex1.Message);
                Console.ResetColor();
            }
            catch (SecurityTokenException ex2)
            {
                Console.WriteLine(ex2.Message);
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }

            return authorizedModel;
        }

        private static async Task<ICollection<SecurityKey>> GetSigningKeys(string issuer)
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
    }
}