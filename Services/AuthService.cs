using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using SecureApi.Data;
using SecureApi.Models;
using Microsoft.IdentityModel.Tokens;
using SecureApi.Helpers;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;

namespace SecureApi.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMapper _map;
    private readonly JwtSettings _jwt;
    private readonly SignInManager<ApplicationUser> _signin;
    private readonly RoleManager<IdentityRole> _role;
    public AuthService(
        UserManager<ApplicationUser> userManager,
        IMapper maper,
        IOptions<JwtSettings> jwt,
        SignInManager<ApplicationUser> signIn,
        RoleManager<IdentityRole> role)
    {
        _userManager = userManager;
        _map = maper;
        _jwt = jwt.Value;
        _signin = signIn;
        _role = role;
    }
    [Obsolete]
    public async Task<AuthModel> GetTokenAsync(LoginModel model)
    {
        var authModel = new AuthModel();
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
        {
            authModel.Message = "Incorrect Email or Password!";
            return authModel;
        }
        var result = await _signin.PasswordSignInAsync(user, model.Password, false, true);
        if (!result.Succeeded)
        {
            authModel.Message = "Something went wrong!";
            return authModel;
        }
        if (user.RefreshTokens!.Any(t => t.IsActive))
        {
            var activeRefreshToken = user.RefreshTokens?.FirstOrDefault(t => t.IsActive);
            authModel.RefreshToken = activeRefreshToken?.Token;
            authModel.RefreshTokenExpiration = activeRefreshToken!.ExpiresOn;
        }
        else
        {
            var refreshToken = GenerateRefreshToken();
            authModel.RefreshToken = refreshToken?.Token;
            authModel.RefreshTokenExpiration = refreshToken!.ExpiresOn;
            user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(user);
        }
        var jwtSecurityToken = await CreateJwtToken(user);
        var roles = await _userManager.GetRolesAsync(user);
        authModel.UserName = user.UserName;
        authModel.IsAuthenticated = true;
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        authModel.ExpiresOn = jwtSecurityToken.ValidTo;
        authModel.Roles = roles.ToList();
        return authModel;
    }

    public async Task<AuthModel> RegisterAsync(RegisterModel model)
    {
        if (await _userManager.FindByEmailAsync(model.Email) is not null)
            return new AuthModel { Message = "Email is already registered!" };
        if (await _userManager.FindByNameAsync(model.UserName) is not null)
            return new AuthModel { Message = "Username is already registered!" };

        var user = _map.Map<ApplicationUser>(model);
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            var errors = "";
            foreach (var error in result.Errors)
                errors += $"{error.Description} , ";
            return new AuthModel { Message = errors };
        }
        await _userManager.AddToRoleAsync(user, "User");
        var jwtSecurityToken = await CreateJwtToken(user);
        return new AuthModel
        {
            IsAuthenticated = true,
            Roles = new List<string> { "User" },
            UserName = user.UserName,
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            ExpiresOn = jwtSecurityToken.ValidTo
        };
    }

    public async Task<string> AddToRoleAsync(Add2RoleMode model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId!);
        var role = await _role.FindByNameAsync(model.RoleName!);
        if (user is null || role is null)
            return "UserName or RoleId is invalid!";
        if (await _userManager.IsInRoleAsync(user, role.Name!))
            return "User already assigned to this role!";
        var result = await _userManager.AddToRoleAsync(user, role.Name!);
        return (!result.Succeeded) ? result.Errors.ToString()! : "";
    }
    [Obsolete]
    public async Task<AuthModel> RefreshTokenAsync(string token)
    {
        var authModel = new AuthModel();
        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens!.Any(t => t.Token == token));
        if (user is null)
        {
            authModel.Message = "invalid token";
            return authModel;
        }
        var refreshToken = user.RefreshTokens?.Single(t => t.Token == token);
        if (!refreshToken!.IsActive)
        {
            authModel.Message = "inactive token";
            return authModel;
        }
        refreshToken.RevokedOn = DateTime.UtcNow;
        var newRefreshToken = GenerateRefreshToken();
        user.RefreshTokens?.Add(newRefreshToken);
        await _userManager.UpdateAsync(user);
        var jwtToken = await CreateJwtToken(user);
        var roles = await _userManager.GetRolesAsync(user);
        authModel.IsAuthenticated = true;
        authModel.RefreshToken = newRefreshToken.Token;
        authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
        authModel.ExpiresOn = jwtToken.ValidTo;
        authModel.UserName = user.UserName;
        authModel.Roles = roles.ToList();
        return authModel;
    }
    public async Task<bool> RevokeTokenAsync(string token)
    {
        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens!.Any(t => t.Token == token));
        if (user is null)
            return false;
        var refreshToken = user.RefreshTokens?.Single(t => t.Token == token);
        if (!refreshToken!.IsActive)
            return false;

        refreshToken.RevokedOn = DateTime.UtcNow;
        user.RefreshTokens!.Add(refreshToken);
        await _userManager.UpdateAsync(user);
        return true;
    }
    private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
    {
        var userClaims = await _userManager.GetClaimsAsync(user);
        var userRoles = await _userManager.GetRolesAsync(user);
        var roleClaims = new List<Claim>();
        foreach (var role in userRoles)
            roleClaims.Add(new Claim("role", role));
        var claims = new[]{
            new Claim(JwtRegisteredClaimNames.Sub,user.UserName!),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email,user.Email!),
            new Claim("uid",user.Id)
        }
        .Union(userClaims)
        .Union(roleClaims);
        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
        var sgningCredintials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        return new JwtSecurityToken(issuer: _jwt.Issure,
        audience: _jwt.Audience
        , expires: DateTime.Now.AddMinutes(_jwt.Duration),
        claims: claims,
        signingCredentials: sgningCredintials
        );
    }
    [Obsolete]
    private RefreshToken GenerateRefreshToken()
    {
        var arr = new byte[32];
        var generator = new RNGCryptoServiceProvider();
        generator.GetBytes(arr);

        return new RefreshToken
        {
            Token = Convert.ToBase64String(arr),
            ExpiresOn = DateTime.UtcNow.AddDays(10),
            CreatedOn = DateTime.UtcNow
        };
    }
}