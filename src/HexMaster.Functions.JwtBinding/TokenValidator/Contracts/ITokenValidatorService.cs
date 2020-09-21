using System.Net.Http.Headers;
using HexMaster.Functions.JwtBinding.Model;

namespace HexMaster.Functions.JwtBinding.TokenValidator.Contracts
{
    public interface ITokenValidatorService
    {
        AuthorizedModel ValidateToken(
            AuthenticationHeaderValue value,
            string issuer,
            string audience,
            string signature);
    }
}