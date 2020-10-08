using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public class IdentityNotAllowedException : AuthorizationScopesException
    {
        public IdentityNotAllowedException(string message, Exception inner = null) : base(
            $"Identity provided in the `sub` claim is not authorizied to contact this endpoint.{Environment.NewLine}{message}",
            inner)
        {
        }
    }
}