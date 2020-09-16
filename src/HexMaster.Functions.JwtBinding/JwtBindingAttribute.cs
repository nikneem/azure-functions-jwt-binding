using System;
using Microsoft.Azure.WebJobs.Description;

namespace HexMaster.Functions.JwtBinding
{

    [Binding]
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.ReturnValue)]
    public class JwtBindingAttribute : Attribute
    {

        public JwtBindingAttribute(string issuer = null, string audience = null)
        {
            Issuer = issuer;
            Audience = audience;
        }

        public string Scopes { get; set; }
        [AutoResolve] public string Audience { get; set; }
        [AutoResolve] public string Issuer { get; set; }

    }

}