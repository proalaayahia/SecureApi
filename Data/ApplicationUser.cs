using Microsoft.AspNetCore.Identity;
using SecureApi.Models;

namespace SecureApi.Data;

public class ApplicationUser : IdentityUser
{
    public List<RefreshToken>? RefreshTokens { get; set; }
}