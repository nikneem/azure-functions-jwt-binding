using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public class IssuerPatternValidationException : Exception
    {
        internal IssuerPatternValidationException(string issuer, string pattern)
            : base($"The issuer '{issuer}' does not match the pattern '{pattern}', token validation failed")
        {
        }
    }
}