using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddScoped<AuthService>();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

app.Use((ctx, next) =>
{
  var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
  var protector = idp.CreateProtector("auth-cookie");

  var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth="));
  var protectedPayload = authCookie.Split("=").Last();
  var payload = protector.Unprotect(protectedPayload);
  var parts = payload.Split(":");
  var key = parts[0];
  var val = parts[1];

  Console.WriteLine(key, val);

  var claims = new List<Claim>
  {
      new(key, val)
  };
  var identity = new ClaimsIdentity(claims);
  ctx.User = new ClaimsPrincipal(identity);

  return next();
});

app.MapGet("/username", (HttpContext ctx) =>
{
  return ctx.User.FindFirst("usr").Value;
});

app.MapGet("/login", (AuthService auth) =>
{
  auth.SignIn();
  return "ok";
});

app.Run();


public class AuthService
{
  private readonly IDataProtectionProvider _idp;
  private readonly IHttpContextAccessor _accessor;

  public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
  {
    _idp = idp;
    _accessor = accessor;
  }

  public void SignIn()
  {
    var protector = _idp.CreateProtector("auth-cookie");
    _accessor.HttpContext.Response.Headers.SetCookie = $"auth={protector.Protect("usr:nagy")}";
  }
}