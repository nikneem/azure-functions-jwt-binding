using System;
using Microsoft.Azure.WebJobs.Description;

namespace HexMaster.Functions.JwtBinding
{

    [Binding]
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.ReturnValue)]
    public class JwtBindingAttribute : Attribute
    {
        public JwtBindingAttribute()
        {
        }

        public JwtBindingAttribute(string issuer)
        {
            Issuer = issuer;
        }

        public JwtBindingAttribute(string issuer, string audience)
        {
            Issuer = issuer;
            Audience = audience;
        }

        public string Scopes { get; set; }
        [AutoResolve] public string Audience { get; set; }
        [AutoResolve] public string Issuer { get; set; }
        [AutoResolve] public string Signature { get; set; }

    }
}