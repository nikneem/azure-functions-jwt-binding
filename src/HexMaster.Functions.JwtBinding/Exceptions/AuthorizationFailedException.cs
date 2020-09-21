using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public sealed class AuthorizationFailedException : Exception
    {

        internal AuthorizationFailedException(Exception innerException)
            : base("JWT Token Validation failed, request not authorized", innerException)
        {
        }

    }
}