using SecureApi.Models;

namespace SecureApi.Services;

public interface IAuthService
{
    Task<AuthModel> RegisterAsync(RegisterModel model);
    Task<AuthModel> GetTokenAsync(LoginModel model);
    Task<string> AddToRoleAsync(Add2RoleMode model);
    Task<AuthModel> RefreshTokenAsync(string token);
    Task<bool> RevokeTokenAsync(string token);
}