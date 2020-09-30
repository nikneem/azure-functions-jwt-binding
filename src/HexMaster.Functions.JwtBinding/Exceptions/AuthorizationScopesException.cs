using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public class AuthorizationScopesException: Exception
    {
        public AuthorizationScopesException(string message, Exception inner = null) : base(message, inner)
        {
        }
    }
}
