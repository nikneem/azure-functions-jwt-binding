using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public sealed class AuthorizationOperationException : Exception
    {
        internal AuthorizationOperationException()
            : base("Could not validate JWT Token because the token could not be retrieved from a valid HTTP Context")
        {
        }
    }
}
