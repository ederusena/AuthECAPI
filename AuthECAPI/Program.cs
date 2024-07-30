
using AuthECAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

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

            app.Run();

           
        }
       
    }
    public class UserRegistration
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FullName { get; set; }
    }
}
