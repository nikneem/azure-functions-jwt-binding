using System;
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

        public JwtBindingAttribute(string issuer = null, string audience = null, string scopes = null, string roles = null, string signature = null, string allowedIdentities = null)
        {
            Issuer = issuer;
            Audience = audience;
            Scopes = scopes;
            Roles = roles;
            Signature = signature;
            AllowedIdentities = allowedIdentities;
        }

        [AutoResolve] 
        [Description("Comma seperated scopes, these scopes must be present in the JWT Token to validate succesfully")]
        public string Scopes { get; set; }

        [AutoResolve] 
        [Description("Comma seperated roles, these roles must be present in the JWT Token to validate succesfully")]
        public string Roles { get; set; }
        
        [AutoResolve] 
        [Description("When passed, the token validator will validate if the passed token at least contains the given audience. When the audience is set to null or empty, the audience validation will not be done.")]
        public string Audience { get; set; }
        
        [AutoResolve] 
        [Description("The name of your token issuer. Usually this is the base URL of all services you call to authorize")]
        public string Issuer { get; set; }
        
        [AutoResolve] 
        [Description("Pass in a valid symmetric security signing key. If no signature is passed, the validator will try to download them from your token provider. When that fails, the token validation fails.")]
        public string Signature { get; set; }
        
        [AutoResolve] 
        [Description("Pass in a valid base64-encoded X509 certificate public key. If there is no value for Signature nor X509CertificateSigningKey parameter, the validator will try to download the signing keys from your token provider, i.e. Issuer. When that fails, the token validation fails.")]
        public string X509CertificateSigningKey { get; set; }

        [AutoResolve]
        [Description("Comma seperated identifiers of identities which are allowed. This will try to be matched on the `sub` claim of the token.")]
        public string AllowedIdentities { get; set; }
    }
}