using System;
using HexMaster.Functions.JwtBinding.Exceptions;

namespace HexMaster.Functions.JwtBinding.TokenValidator
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