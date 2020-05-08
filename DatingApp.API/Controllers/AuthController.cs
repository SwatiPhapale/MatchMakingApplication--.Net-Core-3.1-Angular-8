using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;
            
        }
        [HttpPost("Register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            //Validate Request
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
                
            userForRegisterDto.Username=userForRegisterDto.Username.ToLower();
            if(await _repo.UserExists(userForRegisterDto.Username))
            return BadRequest("UserName Already Exist");

            var UserToCreate = new  User
            {
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register(UserToCreate, userForRegisterDto.Username);
            return StatusCode(201);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFormRepo = await _repo.Login(userForLoginDto.Username.ToLower(),userForLoginDto.Password);
            
            if(userFormRepo == null)
            {
                    return Unauthorized();
            }
            var claims = new []
            {
                new Claim(ClaimTypes.NameIdentifier,userFormRepo.Id.ToString()),
                new Claim(ClaimTypes.Name,userFormRepo.Username)
            };

            var key= new SymmetricSecurityKey(Encoding.UTF8
            .GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.Aes256CbcHmacSha512);

            var TokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds 
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(TokenDescriptor);

            return Ok(new {
                token=tokenHandler.WriteToken(token)
            });

        }
    }
}