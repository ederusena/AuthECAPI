
using AuthECAPI.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthECAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // Services from Identity Core
            builder.Services
                .AddIdentityApiEndpoints<AppUser>()
                .AddEntityFrameworkStores<AppDbContext>();

            builder.Services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.User.RequireUniqueEmail = true;
            });

            builder.Services.AddDbContext<AppDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DevDB")));

            builder.Services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme =
                x.DefaultChallengeScheme =
                x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(y =>
            {
                y.SaveToken = false;
                y.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(
                            builder.Configuration["AppSettings:JWTSecret"]!))
                };
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            # region Config. CORS
            app.UseCors();
            #endregion

            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();

            app
                .MapGroup("/api")
                .MapIdentityApi<AppUser>();

            app.MapPost("/api/signup", async (UserManager<AppUser> userManager, [FromBody] UserRegistration user) =>
            {
                AppUser appUser = new AppUser
                {
                    UserName = user.Email,
                    Email = user.Email,
                    FullName = user.FullName
                };

                var result = await userManager.CreateAsync(appUser, user.Password);

                if (result.Succeeded)
                    return Results.Created($"{appUser.Id}", appUser);
                else
                    return Results.BadRequest(result);
            });

            app.MapPost("/api/signin", async (
                UserManager<AppUser> userManager,
                [FromBody] LoginModel loginModel) =>
                {
                    var user = await userManager.FindByEmailAsync(loginModel.Email);
                    if (user != null && await userManager.CheckPasswordAsync(user, loginModel.Password))
                    {
                        var signKey = new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(app.Configuration["AppSettings:JWTSecret"]!));
                        var tokenDecriptor = new SecurityTokenDescriptor
                        {
                            Subject = new ClaimsIdentity(new Claim[]
                            {
                                new Claim("UserID", user.Id.ToString())
                            }),
                            Expires = DateTime.UtcNow.AddDays(1),
                            SigningCredentials = new SigningCredentials(signKey, SecurityAlgorithms.HmacSha256Signature)
                        };
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var securityToken = tokenHandler.CreateToken(tokenDecriptor);
                        var token = tokenHandler.WriteToken(securityToken);
                        return Results.Ok(new { token });

                    }
                    else
                    {
                        return Results.BadRequest("Invalid login attempt");
                    }
                });

            app.Run();


        }

    }
    public class UserRegistration
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FullName { get; set; }
    }

    public class LoginModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
