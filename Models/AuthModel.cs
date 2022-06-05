using System.Text.Json.Serialization;

namespace SecureApi.Models;

public class AuthModel
{
    public string? Message { get; set; }
    public string? UserName { get; set; }
    public string? Token { get; set; }
    public bool IsAuthenticated { get; set; }
    public DateTime ExpiresOn { get; set; }
    public List<string>? Roles { get; set; }
    [JsonIgnore]
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiration { get; set; }



}