using Microsoft.AspNetCore.Mvc;
using SecureApi.Models;
using SecureApi.Services;

namespace SecureApi.Controllers;
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService service;
    public AuthController(IAuthService _service)
    {
        service = _service;
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody]RegisterModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        var result = await service.RegisterAsync(model);
        if (!result.IsAuthenticated)
            BadRequest(result.Message);
        //SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
        return Ok(result);
    }
    [HttpGet("login")]
    public async Task<IActionResult> Login(LoginModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        var result = await service.GetTokenAsync(model);
        if (!result.IsAuthenticated)
            BadRequest(result.Message);
        if (!string.IsNullOrEmpty(result.RefreshToken))
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
        return Ok(result);
    }
    [HttpPost("add2role")]
    public async Task<IActionResult> AddToRoleAsync(Add2RoleMode model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        var result = await service.AddToRoleAsync(model);
        return string.IsNullOrEmpty(result) ? Ok(result) : BadRequest(result);
    }
    [HttpGet("refreshToken")]
    public async Task<IActionResult> RefreshTokenAsync()
    {
        var rtoken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(rtoken))
            return BadRequest("invalid token");
        var result = await service.RefreshTokenAsync(rtoken);
        if (!result.IsAuthenticated)
            return BadRequest(result.Message);
        SetRefreshTokenInCookie(result.RefreshToken!, result.RefreshTokenExpiration);
        return Ok(result);
    }
    [HttpPost("revokeToken")]
    public async Task<IActionResult> RevokeTokenAsync([FromBody] RevokeModel model)
    {
        var token = model.Token ?? Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(token))
            return BadRequest("token is required!");
        var result = await service.RevokeTokenAsync(token);
        if (!result)
            return BadRequest("invalid token!");
        return Ok();
    }
    private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
    {
        CookieOptions cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = expires.ToLocalTime()
        };
        Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
    }
}