using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using HexMaster.Functions.JwtBinding.Model;
using Microsoft.IdentityModel.Tokens;

namespace HexMaster.Functions.JwtBinding.Helpers
{
    public static class TokenValidator
    {
        public static AuthorizedModel ValidateToken(
            AuthenticationHeaderValue value,
            string audience,
            string issuer)
        {
            var authorizedModel = new AuthorizedModel();
            if (value?.Scheme != "Bearer")
                return null;

            var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidAudience = audience,
                ValidateAudience = !string.IsNullOrWhiteSpace(audience),
                ValidIssuer = issuer,
                ValidateIssuer = !string.IsNullOrWhiteSpace(issuer),
                ValidateIssuerSigningKey = false,
                ValidateLifetime = true,
                SignatureValidator = SignatureValidator
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
                // This exception is thrown if the signature key of the JWT could not be found.
                // This could be the case when the issuer changed its signing keys, so we trigger a 
                // refresh and retry validation.
            }
            catch (SecurityTokenException ex2)
            {
                return null;
            }
            catch (Exception ex)
            {
                return null;
            }

            return authorizedModel;
        }

        private static SecurityToken SignatureValidator(
            string token, 
            TokenValidationParameters validationparameters)
        {
            var st = new JwtSecurityToken(token);
            return st;
        }
    }
}