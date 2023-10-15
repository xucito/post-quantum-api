using PostQuantumLab.API.Authorization.Model;
using PostQuantumLab.API.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace PostQuantumLab.API.Authorization
{
    public class JwtAuthenticationSchemeHandler : AuthenticationHandler<JwtAuthenticationSchemeOptions>
    {
        private readonly ApplicationDbContext _applicationDbContext;
        public JwtAuthenticationSchemeHandler(
            IOptionsMonitor<JwtAuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ApplicationDbContext applicationDbContext) : base(options, logger, encoder, clock)
        {
            _applicationDbContext = applicationDbContext;
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                return AuthenticateResult.Fail("Header Not Found.");
            }

            var header = Request.Headers[HeaderNames.Authorization].ToString();
            var jwtToken = new JwtToken(header.Split(" ")[1]);
            var userId = new Guid(jwtToken.sub);
            var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
            {
                return AuthenticateResult.Fail("User Not Found.");
            }

            jwtToken.VerifySignature(Convert.ToBase64String(user.PublicKey));

            // create claims array from the model
            var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.Name) };

            // generate claimsIdentity on the name of the class
            var claimsIdentity = new ClaimsIdentity(claims, nameof(JwtAuthenticationSchemeHandler));

            // generate AuthenticationTicket from the Identity
            // and current authentication scheme
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);

            // pass on the ticket to the middleware
            return AuthenticateResult.Success(ticket);
        }
    }
}
