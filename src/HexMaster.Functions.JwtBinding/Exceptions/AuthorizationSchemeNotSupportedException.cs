using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public sealed class AuthorizationSchemeNotSupportedException : Exception
    {
        internal AuthorizationSchemeNotSupportedException(string scheme) :
            base($"The authorization scheme '{scheme}' is not supported. Please use the Bearer scheme")
        {
        }
    }
}