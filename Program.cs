using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SampleMvcApp.Support;
using System.Net;

using Microsoft.IdentityModel.Logging;
using Microsoft.OpenApi.Models;
using JWT;
using JWT.Exceptions;
using JWT.Extensions.AspNetCore;
using System;
using System.Security.Cryptography;
using JWT.Algorithms;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
}).AddJwt(options => { });

string privateKeyStr = System.IO.File.OpenText(Environment.CurrentDirectory + "/private.key").ReadToEnd()
                .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Trim();
byte[] privateKey = Convert.FromBase64String(privateKeyStr);

RSA rsa = RSA.Create();
rsa.ImportPkcs8PrivateKey(privateKey, out _);
RSA rsaPublic = RSA.Create();
rsaPublic.ImportRSAPublicKey(rsa.ExportRSAPublicKey(), out _);
IJwtAlgorithm algorithm = new RS256Algorithm(rsaPublic, rsa);

builder.Services.AddSingleton(new DelegateAlgorithmFactory(algorithm));

//To use MVC we have to explicitly declare we are using it. Doing so will prevent a System.InvalidOperationException.
builder.Services.AddControllersWithViews();

//builder.WebHost.UseStartup<SampleMvcApp.Startup>();


// Configure the HTTP request pipeline.
builder.Services.ConfigureSameSiteNoneCookies();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT Test", Version = "v1" });
});
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseAuthentication();
app.UseSwagger();
app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT Test v1"));

app.UseStaticFiles();
app.UseCookiePolicy();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();