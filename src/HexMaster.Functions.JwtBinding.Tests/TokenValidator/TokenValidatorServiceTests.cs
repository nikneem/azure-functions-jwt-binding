using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HexMaster.Functions.JwtBinding.Configuration;
using HexMaster.Functions.JwtBinding.Exceptions;
using HexMaster.Functions.JwtBinding.Model;
using HexMaster.Functions.JwtBinding.TokenValidator;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;

namespace HexMaster.Functions.JwtBinding.Tests.TokenValidator
{
    [TestFixture]
    public class TokenValidatorServiceTests
    {

        private Mock<ILogger<TokenValidatorService>> _loggerMock;
        private TokenValidatorService _service;
        private string _audience;
        private string _issuer;
        private string _issuerPattern;
        private string _scheme;
        private string _token;
        private string _subject;
        private string _symmetricSigningKey;
        private string _givenName;
        private string _scopes;
        private string _allowedIdentities;
        private string _certificateWithPrivateKey;
        private string _certificateWithPublicKey;

        [SetUp]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<TokenValidatorService>>();
            _service = new TokenValidatorService(_loggerMock.Object);
        }

        [Test]
        public void WhenTokenWithSymmetricSignatureIsValid_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            var model = Validate();

            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenTokenWithX509CertificateSingingKeyIsValid_ThenItReturnsAuthorizedModel()
        {
            WithValidX509CertificateSigningKey();
            WithValidJwtToken();
            var model = Validate();

            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenTokenWithX509CertificateSingingKeyIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithInvalidX509CertificateSigningKey();
            WithValidJwtToken();

            var exception = Assert.Throws<AuthorizationFailedException>(Act);
            Assert.That(exception.Message.Contains("Signature validation failed. Unable to match key"));
        }

        [Test]
        public void WhenTokenSchemeIsInvalid_ThenItThrowsAuthorizationSchemeNotSupportedException()
        {
            WithValidJwtToken();
            WithInvalidScheme();
            Assert.Throws<AuthorizationSchemeNotSupportedException>(Act);
        }

        [Test]
        public void WhenTokenWithSymmetricSignatureIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidSignature();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenIssuerIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidIssuer();
            WithoutIssuerPattern();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenIssuerIsNull_ThenItThrowsConfigurationException()
        {
            WithValidJwtToken();
            WithEmptyIssuer();
            Assert.Throws<ConfigurationException>(Act);
        }

        [Test]
        public void WhenTokenAudienceIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidAudience();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenTokenScopeIsInvalid_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidScopes();
            Assert.Throws<AuthorizationFailedException>(Act);
        }

        [Test]
        public void WhenAllowedIdenityIsInvalid_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            WithoutAllowedIdentitiesSpecified();
            var model = Validate();
            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenMultipleAllowedIdentitiesSpecified_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            WithAllowedIdentitiesSpecifiedMatchingTheSubject();
            var model = Validate();
            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenAllowedIdentitiesSpecifiedMatchingTheSubject_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            WithAllowedIdentitiesSpecifiedMatchingTheSubject();
            var model = Validate();
            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }

        [Test]
        public void WhenMultipleAllowedIdentitiesSpecifiedAndNoneAreInTheToken_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithMultipleAllowedIdentitiesSpecifiedAndNoneAreInTheSubject();
            var ex = Assert.Throws<AuthorizationFailedException>(Act);
            Assert.That(ex.InnerException.GetType(), Is.EqualTo(typeof(IdentityNotAllowedException)));
        }

        [Test]
        public void WhenInvalidIssuerButValidIssuerPatternInTheToken_ThenItReturnsAuthorizedModel()
        {
            WithValidJwtToken();
            WithInvalidIssuer();
            WithValidIssuerPattern();
            var model = Validate();
            Assert.AreEqual(model.Subject, _subject);
            Assert.AreEqual(model.Name, _givenName);
        }
        [Test]
        public void WhenInvalidIssuerAndInvalidIssuerPatternInTheToken_ThenItThrowsAuthorizationFailedException()
        {
            WithValidJwtToken();
            WithInvalidIssuerPattern();
            var ex = Assert.Throws<AuthorizationFailedException>(Act);
            Assert.That(ex.InnerException.GetType(), Is.EqualTo(typeof(IssuerPatternValidationException)));
        }

        private void WithInvalidScheme()
        {
            _scheme = "Invalid";
        }

        private void WithInvalidSignature()
        {
            _symmetricSigningKey = Guid.NewGuid().ToString();
        }

        private void WithInvalidIssuer()
        {
            _issuer = "https://my-random-issuer.com";
        }

        private void WithEmptyIssuer()
        {
            _issuer = null;
        }

        private void WithInvalidAudience()
        {
            _audience = "invalid-audience";
        }

        private void WithInvalidScopes()
        {
            _scopes = "nothing:nothing";
        }
        
        private void WithoutIssuerPattern()
        {
            _issuerPattern = string.Empty;
        }
        private void WithValidIssuerPattern()
        {
            _issuerPattern = "https://my.*";
        }
        private void WithInvalidIssuerPattern()
        {
            _issuerPattern = "eduard";
        }

        private void WithoutAllowedIdentitiesSpecified()
        {
            _allowedIdentities = null;
        }
        private void WithAllowedIdentitiesSpecifiedMatchingTheSubject()
        {
            _allowedIdentities = _subject;
        }
        private void WithMultipleAllowedIdentitiesSpecified()
        {
            _allowedIdentities = $"Some,More,{_subject},Identities";
        }

        private void WithMultipleAllowedIdentitiesSpecifiedAndNoneAreInTheSubject()
        {
            _allowedIdentities = $"Some,More,Identities";
        }

        private void WithValidX509CertificateSigningKey()
        { 
            _certificateWithPrivateKey = @"MIINugIBAzCCDXYGCSqGSIb3DQEHAaCCDWcEgg1jMIINXzCCBgAGCSqGSIb3DQEHAaCCBfEEggXtMIIF6TCCBeUGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAjv464XE0Z4nAICB9AEggTYKFKZSgNvHodiWQcf07Ly0F0TodeHD8UgBnokwIGtwUKUafzeF9xFoC3IyP+NQv88lC16gRMpuUbjoW7BwMyajdWweShlHN8eGFWWeh9EztbcOnMZEu1SGe022LMasfP9MVE1+PqY+XoHiP4GQo2+79wxtjABFno/z68sMcoDOSGyGuZ4KV4jMh/S7Uj4YjuyfzfYJRL0uAuuq9IUo9+1psCZpIdrr8vjKImyqz6XMNlbabcdHPYxatfNZooQFMuWp5CtBPgELalwY9sgU4je/pVIGkeb0D/jVfGig3FY0Qprcm0GelkhKNT1sQvYsFfJ1/37qDaF+PApxbDTxMOYzn99lwpKNVreHX+b5ZxPiIE8jebYJzv03kfxEPd+JqSwLpcwgDW8IOwh4tVxN2baR+v5mV3yWPzImpC3Wfz4OxBy4sDlcgsHhVlfvPn5iIV1mNOrOcbEea6J0QYWBfl0wl5NedsERon/WD8PQjdEZXkiiWYncJ1DQQtnKE+OTjkQ/H0eS4gEq6sjB/++gACscTrnDmFX36tM8kTbzRa9I3Ip9HY5SlvE5cYNNUdfkRV1+QZI2Ht0ow97GmuZOQg6eoUwjOPWu59m0tYu28Sram4ilvHVjbrw7LUgsIy/4w9S6l7SAxgvPtTrsbNrXRM2zIFLtRMPDf7Zpddp6jkKiBU9oiJYbZdoIRj180amdHOllFy50TBgzi1VH1jtffuUoRlrqMdaUX1mKK4mzf0YmKLLiVXk+k8vumv1ZYFO7MKCwscpEtxOHbdO2Y4BPhcItvNDFgxdUJ9gcWJJnr+P0oN2y7iRRHQvVAhIixgJLX6WMSAYT68r5cSn8ARdgyqqfZNkf5Hw5b2G2Cy4xaEhA31dySE0hmaufs6HGoOMbk8YWn2u9jdUJjMib3PFArhApd8C65AmBRds/0gYwRg9zKpluHl8TLe4QbYyxfHesyz8mgZqwXrGjJXpcKVd2tAoU/BOHQnjRW+rd60RoEZqqpHUuv043VHDhwOjSvRYL/HCsgh0yoxxS4Ejat1uq8zu0teiAHPC/wuCDns2tgByoBxQikxL2EN2eIKAWMNymRzWmBTr15PNVFnsvV4wkM/hG6OcXKZ5vnOWufhrqUgiDJ6HY5Y6BsYb/dotEaCwYHu8qFjC36JuQRmIByXc0vgA+BYusoUZmonGJ1euRux8nL+MttcoW0V2/pJyANHN/XrGAqapJaANT+yAjVvsuprFneQvveBqQvoN7fBCsMuubmQXj32TCA6WcZamCmJ1SjBruNgYUvIQsMYJvOqg2teeanVDsx87ESn/bgKCoodoHu0VHzdUO84HGB8j8vmSm+3XxS6NHuIH9CjWOd5QPWdyCdAuS917zPYjfBxFk0ZitdJwtqFY0MkicYOKrzxiaWapTkD0pOapsonBF3MYskduTs1QdKMUNY6lG26REP0BWvEhFoyrwXZxAwyDltU3amtT9/eGEEtPRTQyS1wXB6ON1iFg/f9BouV833/OOi4i/HY3HiNnvrPaXZsOSz80mzXLnQv/ewN7a+5EHECXjn2fOsXis2g4K8QZtCxL4XbLE4I6+U+ByXYbhWs3ZrISxJlS/WFLZne2ofPLTB7TZi7ZgjIgU/4qwj5lF9qTxBpkLnBzmolFNpxqZjGB0zATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtADkANQBlADAAYgBkADMAZQAtAGEAZgBlAGYALQA0AGMAZQAxAC0AYgBlADMANAAtADYAMwBkADkAMwAzAGMAZAA4ADgAYwBmMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIwggdXBgkqhkiG9w0BBwagggdIMIIHRAIBADCCBz0GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECK+7mR3nziknAgIH0ICCBxCH90rpIOQJmWz8hmKST01YpqN0sXUQOiracC1EDvEI4DItrEKsYUG/ubPOwqkQPOs76xhxiL5sUifmngbg6eKND1rC/vEVD0hu8C5Sc8g/cP8F9L9Rr1PIkpIQ/iOEejaUzsl8byQauqteHpGrcLSpSBoz1HfdP0puEtye8uWotsc+mpQWuajAPo1OI4T4TCLF/03iRYM4VYmSS/7GjhXft3Wrwm6ZZNdzM7pDnzpCfHEvnjOgJh9RvpZs9Uk19S2fpbb5ZqbO4G3dPnSQbFn11Bjf5TMVuZqWLKjyz5pBNetTEezGg2CVGJbG5OG+7LNF41//j1rj2AzNqoR4CTewCPVzr5w/l1VSzZX6HNKDUeybf3nYIKJ3ilKqzif9K5K87C/JnVb3ZGjEBKMMV/GUu3jUWZmRnTIB7K0Ibm4vpecOC5GZsIkdwIT+J7VZiUV+g/grNTwFPS1bjBetr0gDMJF30jrn+iGHaj9KrH1LzXNiNezh7cQ4GmHHguftpzF666M9kAKvO/czqPGqmpC7TvwCIxAHeCORg97N8CIJ5oFV8XSMJ5uOupq8ZRfbLp0Us38y9xqjUuSkj4Vw8fvEeFf6YLlKn9QgMu9yl5g8nZENqKtrS52+z+iOq3To71WFGoFqUMx8fTP/il5F++l4uHiJZ0G8orHZJqqpt1OeZrWD8o4wYOvtc1YCTVBbOTKrpYrlRtizBFPUfWYAyqupK0Kr0yculXPjzGCnNXTyQQDfLhWHXlU6DITPHgkMa5jp1455sULJz+3cfkcp6LrKIrbnsd96CqqrWz8Kuu9zj8TipWh33nah3fd6Dd6Kbb1YfgwaEy9X6Ckc4WqTsjM+ZoXtVSEaxLK537UJDDgf0sA1cWwl52fGKpoI5V25J8VnpwMeSepqcMOvsPMaaoYXfdcvpnXGUlqdwfHJDlYBKuwJyEczBs2J/W5QKoBHtSA2dxbm1Lo1p98Xj8tAP1of/r51rSDTxpo9Dg/d3/Pz72+EsTjNzF5aByZ+hOR7h5gTISese+5q0jax/Bw5x0m8sh4L4ENtU3OJJGlTD2MGnrQQRLWYcacmJyLMtJeKSI5s65ICeIT1mKiMmMWZochvVjcU54beBOqN0VZbV87pfvV4Erc5cYm0/fEcfoL0dC9kZVbwou5OPeqNCexzEktJ8lzddXLf1zIbDcT3ChsuFAAFZTs1ZyKWmsOMVYl7KlXs4oH574iETxrmOdG2xg392R2VieGvyBh+GeyjY6EKoLyZUBS8Vwlho/Z0y+UbM4BKIskPPchbw+zaexjpAfun1moPnJ3uo6bhHbxKFv5wnJeHzPXqJK1lXf16XeWwLAXTbk4de1ncwfqrHfSKB4eR5EoIz9vo82kc16PaHrQUln/JaWIDKkazRFemZULjWBcpWff0ws8uHiET6e15N/SaRK2NgPgkTLK0ZFokYzTfPhHQnRYDVH+xpehp3t1V+IDboiQSKxhFKLzDBeUeaTFyc3Als9+v2vDSuXg9JaVYl4UEOadX/6i15HfLgxg7307EnLQh8wBhoWA1ay/G9KuWYNyaL3RYqDuV9lgbpK/6lan2WKys2IBCNDnX1xdyT8Hsy0OAwxfWQZ6cbCGuVXThcFcXieVH0fIMiBCWvM4ZU1xCUAlHPtSaoxGKsS5R54n3W6dSa+IHN5HrxnCMuu6zL1t1We9UIwfSuE6ljQiKyv6t8gdR3LrYqGZ2HE0WS+bw51tgKI9jWczgL+Tbn+W+fWOBFP7PfB2vOlktgub9TboxFhyU/sDgkfhZEv4/hFluGaaRljjbQAbq/B9aFHLevALRFCNiqYneFfNlPKCsje0KAZ/bpre7i2HMI6YaJ+l4k0W5DiVPh8jFYxPd2TPqllnqihBOK+BSxVxgiSjZCmiZpIgmz5YqDdeCakzqX+tt08vzzMSLdiWWxBU/PtbPXQ4XCZ6Imn8b5Jjm0p257ByRyDQ4lwoOP67cIfGs9KDU5flbM0QuqMNgQotP/5F3q982RZHPbkbf9qyaEp6zyv8V7n1rGaT6blD2exVsn5y8eqK9UzlMgbIEipocnGRljTreykRh9IFz5k4F+4LViSaYExIH/kvTvkfuyznEzntEFQmQKJCQVxBaq1E6wUdKtkFYddUoosUx5/KEssn9mS1wJt1oLHd/bBDxip4uqcsVh7lFXF1hevth0E2R08Z+t3lYVhqTSEL7fwUbT8O3BW2MQCOsY5FIPLLZXBj4grF3yQ8CmZik1iDoe1+QwFI/U2utt0KUNMJUAlbdPqBRl7bokOryi1fhWU9iZuQwE1LQ0M2vwW5zAet4HvakZYmPynN5XAeDYeYF7LWk3KDkBpwMGhoPxom6rXo20eYcLMFYLQRXYdLqPdU+pxUNFcxHNv869mzqSq3l9z8r+f5GfDA7MB8wBwYFKw4DAhoEFE1Q4OeADwfAd7gaMP2HfSDEcO4DBBTsS7w1LKPq4BYxyzMxZxq7Ciqp7gICB9A=";
            _certificateWithPublicKey = @"MIIDNDCCAhygAwIBAgIQcp7e+9EiPpBB8ooUqpDchDANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDDARUZXN0MB4XDTIwMTEyMzE2MDI0OVoXDTIxMTEyMzE2MjI0OFowEzERMA8GA1UEAwwIdGVzdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXIlFRldeYCFm0juFRH41nDhat3Vy1eXwnUaEqw8Ws41q3cEh9CCuG86FJoAWc6FhzfxQ8pHcyEFi0koULxyIZNE4YHunB9ANsoLPPdEhsSgF28QYY/M7ZgWOnNL0fd66Z3S8717dsGWIfqy09Z694X1F+wprtd2lEkR4zdQJCLiL5ikiwtOBEo+RknPk+2kOedxq/zdmrItctSDYxsh/+Bm0vHNl3R+hf3nDNoq/xJGNwSeuWwcdwxfud4OLs0sAyD618xzAy92luQmAagVbFqzKumDIDDgaZTCBGCz57minVBHTYgzpktMEZI1J5aEYqvPEDjhxCyujqFeNiCBjZAgMBAAGjgYcwgYQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATATBgNVHREEDDAKggh0ZXN0LmNvbTAfBgNVHSMEGDAWgBSssX5m9KOicRcEr0xpkbiS2b/cITAdBgNVHQ4EFgQUe6sY+2e7cL2m2DnWlmpg/Meyp4cwDQYJKoZIhvcNAQEFBQADggEBAJYBybo/AHyqjuPnQfp8nPRLzMHwwu7iUDDtVrw0VH9dk473UaaCd5JNBBh1FDvgkS/CSYIY2MBIejcHEq2rGAuTuOJnsRWDPipdmReo+KK/feubu78JUofCoWcKTnhO7nMe1rtOIOSSa/LR2mtRliMVa7wSxPXUQv363LKCfMJxNVj5FxoxMDYwzhMBsoagnE03EbkYAJKb1jHqSSoto19PYVMl+y5XPlcomI/P5D50hp2cI4ulYafvQ4rETF9SKSwaeOopK5RiqSvu2fVEfXfaOM0MXS8vyJwHDTeOcwBWIB7gyUl0l9wVTYjlTTajz+RyI8LZVYSVcdmsgHb3S1A=";
        }

        private void WithInvalidX509CertificateSigningKey()
        { 
            _certificateWithPrivateKey = @"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";
            _certificateWithPublicKey = @"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";
        }

        private void WithValidJwtToken()
        {
            _audience = "my-valid-audience";
            _issuer = "https://my-valid-issuer";
            _scheme = "Bearer";
            _subject = $"{DateTime.UtcNow.Ticks}";
            _givenName = "Tommy Token";
            _symmetricSigningKey = Guid.NewGuid().ToString();
            _scopes = "something:create,other:list";
            _allowedIdentities = "";
            _token = CreateJwtToken();
        }

        private string CreateJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Create JWToken
            var signingCredentials = string.IsNullOrWhiteSpace(_certificateWithPrivateKey)
                ? new SigningCredentials(new SymmetricSecurityKey(Encoding.Default.GetBytes(_symmetricSigningKey)),
                    SecurityAlgorithms.HmacSha256Signature)
                : new SigningCredentials(new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(_certificateWithPrivateKey), "SelfSigned_Test")), SecurityAlgorithms.RsaSha256Signature);

            var token = tokenHandler.CreateJwtSecurityToken(
                _issuer,
                _audience,
                CreateClaimsIdentities(),
                DateTime.UtcNow,
                DateTime.UtcNow.AddDays(1),
                signingCredentials: signingCredentials);

            return tokenHandler.WriteToken(token);
        }

        private ClaimsIdentity CreateClaimsIdentities()
        {
            var claimsIdentity = new ClaimsIdentity();
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.NameId, _subject));
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.GivenName, _givenName));

            foreach (var scope in _scopes.Split(','))
            {
                claimsIdentity.AddClaim(new Claim("scp", scope));
            }

            return claimsIdentity;
        }


        private void Act()
        {
            var config = new JwtBindingConfiguration
            {
                SymmetricSecuritySigningKey = _symmetricSigningKey,
                Scopes = _scopes,
                Audience = _audience,
                Issuer = _issuer,
                IssuerPattern = _issuerPattern,
                AllowedIdentities = _allowedIdentities
            };
            _service.ValidateToken(
                new AuthenticationHeaderValue(_scheme, _token),
                config);
        }

        private AuthorizedModel Validate()
        {
            var config = new JwtBindingConfiguration
            {
                Scopes = _scopes,
                Audience = _audience,
                Issuer = _issuer,
                IssuerPattern = _issuerPattern
            };

            if (!string.IsNullOrWhiteSpace(_certificateWithPrivateKey))
            {
                config.X509CertificateSigningKey = _certificateWithPublicKey;
            }
            else
            {
                config.SymmetricSecuritySigningKey = _symmetricSigningKey;
            }

            return _service.ValidateToken(
                new AuthenticationHeaderValue(_scheme, _token),
                config);
        }
    }
}