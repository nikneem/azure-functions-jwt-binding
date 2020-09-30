﻿using System;
using System.ComponentModel;
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
        public JwtBindingAttribute(string issuer, string audience, string scopes)
        {
            Issuer = issuer;
            Audience = audience;
            Scopes = scopes;
        }

        [AutoResolve] 
        [Description("Comma seperated scopes, these scopes must be present in the JWT Token to validate succesfully")]
        public string Scopes { get; set; }
        
        [AutoResolve] 
        [Description("When passed, the token validator will validate if the passed token at least contains the given audience. When the audience is set to null or empty, the audience validation will not be done.")]
        public string Audience { get; set; }
        
        [AutoResolve] 
        [Description("The name of your token issuer. Usually this is the base URL of all services you call to authorize")]
        public string Issuer { get; set; }
        
        [AutoResolve] 
        [Description("Pass in a valid signature key. If no signature is passed, the validator will try to download them from your token provider. When that fails, the token validation fails.")]
        public string Signature { get; set; }

    }
}