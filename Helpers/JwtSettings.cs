namespace SecureApi.Helpers;

public class JwtSettings
{
    public string Key { get; set; } = null!;
    public string Issure { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public double Duration { get; set; }
}