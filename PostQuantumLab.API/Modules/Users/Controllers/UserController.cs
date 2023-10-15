using PostQuantumLab.API.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PostQuantumLab.API.Modules.Users.ViewModels;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using PostQuantum.API.Modules.Users;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace PostQuantumLab.API.Modules.Users.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private ApplicationDbContext _context;
        private UserManager<User> _userManager;
        public UserController(ApplicationDbContext context,
            UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // POST api/<UsersController>
        [AllowAnonymous]
        [HttpPost("sign-up")]
        public async Task<IActionResult> SignUp([FromBody] SignUpVM body)
        {
            var checkUser = await _userManager.FindByEmailAsync(body.Email);
            if (checkUser != null)
            {
                throw new ArgumentException("User already exists");
            }

            var id = Guid.NewGuid();
            var result = await _userManager.CreateAsync(new User
            {
                Id = id,
                Email = body.Email,
                UserName = body.Email,
                PublicKey = Convert.FromBase64String(body.PublicKey),
                Name = body.Email
                //REPLACE IF YOU IMPLEMENT PASSWORD LOGIN TOO
            }, Guid.NewGuid().ToString() + "ASD@FDASFV1894-4100");

            if (!result.Succeeded)
            {
                throw new ArgumentException("User creation failed");
            }
            await _context.SaveChangesAsync();
            return Ok();
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok(await _userManager.GetUserAsync(User));
        }
        
    }
}
