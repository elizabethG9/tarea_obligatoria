using System.Security.Cryptography;
using System.Text;
using courses_dotnet_api.Src.Data;
using courses_dotnet_api.Src.DTOs.Account;
using courses_dotnet_api.Src.Interfaces;
using courses_dotnet_api.Src.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace courses_dotnet_api.Src.Controllers;

public class AccountController : BaseApiController
{
    private readonly IUserRepository _userRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly DataContext _dataContext;

    public AccountController(IUserRepository userRepository, IAccountRepository accountRepository,DataContext dataContext)
    {
        _userRepository = userRepository;
        _accountRepository = accountRepository;
        _dataContext = dataContext;
    }

    [HttpPost("register")]
    public async Task<IResult> Register(RegisterDto registerDto)
    {
        if (
            await _userRepository.UserExistsByEmailAsync(registerDto.Email)
            || await _userRepository.UserExistsByRutAsync(registerDto.Rut)
        )
        {
            return TypedResults.BadRequest("User already exists");
        }

        await _accountRepository.AddAccountAsync(registerDto);

        if (!await _accountRepository.SaveChangesAsync())
        {
            return TypedResults.BadRequest("Failed to save user");
        }

        AccountDto? accountDto = await _accountRepository.GetAccountAsync(registerDto.Email);

        return TypedResults.Ok(accountDto);
    }
    [HttpPost("login")]
    public async Task<IResult> Login (LoginDto loginDto)
    {
       User? user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Email == loginDto.Email);

        if (user == null)
        {
            return TypedResults.BadRequest("Credentials are invalid");
        }

        using (var hmac = new HMACSHA512(user.PasswordSalt))
        {
            byte[] computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            
            if (!computedHash.SequenceEqual(user.PasswordHash))
            {
                return TypedResults.BadRequest("Credentials are invalid");
            }
        }

        AccountDto? accountDto = await _accountRepository.GetAccountAsync(loginDto.Email);
        return TypedResults.Ok(accountDto);
        
    }
}
