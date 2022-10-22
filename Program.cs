//  Copyright 2022 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using IdentityWithoutEF.Data;
using IdentityWithoutEF.Models;
using IdentityWithoutEF.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IIdentityStore, IdentityStore>();
ConfigureIdentity(builder);
builder.Services.AddRazorPages();
ConfigureAuthentication(builder);
ConfigureAuthorization(builder);

var app = builder.Build();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.Run();

void ConfigureIdentity(WebApplicationBuilder builder)
{
    var identityBuilder = builder.Services.AddIdentity<ApplicationUser, ApplicationRole>();

    identityBuilder.AddDefaultUI();
    identityBuilder.AddDefaultTokenProviders();
    identityBuilder.AddUserStore<ApplicationUserStore>();
    identityBuilder.AddRoleStore<ApplicationRoleStore>();
}

void ConfigureAuthentication(WebApplicationBuilder builder)
{
    var authBuilder = builder.Services.AddAuthentication();

    var config = builder.Configuration.GetSection("Authentication");

    if (config.Exists())
    {
        var google = config.GetSection("Google");

        if (google.Exists())
        {
            ConfigureGoogleAuthentication(authBuilder, google);
        }

        var microsoft = config.GetSection("Microsoft");

        if (microsoft.Exists())
        {
            ConfigureMicrosoftAuthentication(authBuilder, microsoft);
        }
    }
}

void ConfigureGoogleAuthentication(AuthenticationBuilder builder, IConfigurationSection config)
{
    builder.AddGoogle(options =>
    {
        var clientId = config.GetValue<string>("ClientId");

        if (clientId != null)
        {
            options.ClientId = clientId;
        }

        var clientSecret = config.GetValue<string>("ClientSecret");

        if (clientSecret != null)
        {
            options.ClientSecret = clientSecret;
        }

        var authorizationEndpoint = config.GetValue<string>("AuthorizationEndpoint");

        if (authorizationEndpoint != null)
        {
            options.AuthorizationEndpoint = authorizationEndpoint;
        }

        var tokenEndpoint = config.GetValue<string>("TokenEndpoint");

        if (tokenEndpoint != null)
        {
            options.TokenEndpoint = tokenEndpoint;
        }
    });
}

void ConfigureMicrosoftAuthentication(AuthenticationBuilder builder, IConfigurationSection config)
{
    builder.AddMicrosoftAccount(options =>
    {
        var clientId = config.GetValue<string>("ClientId");

        if (clientId != null)
        {
            options.ClientId = clientId;
        }

        var clientSecret = config.GetValue<string>("ClientSecret");

        if (clientSecret != null)
        {
            options.ClientSecret = clientSecret;
        }

        var authorizationEndpoint = config.GetValue<string>("AuthorizationEndpoint");

        if (authorizationEndpoint != null)
        {
            options.AuthorizationEndpoint = authorizationEndpoint;
        }

        var tokenEndpoint = config.GetValue<string>("TokenEndpoint");

        if (tokenEndpoint != null)
        {
            options.TokenEndpoint = tokenEndpoint;
        }
    });
}

void ConfigureAuthorization(WebApplicationBuilder builder)
{
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("PrivacyPolicy", config =>
        {
            config.RequireAuthenticatedUser();

            config.RequireRole("PRIVACY"); // Uppercase required.
        });
    });
}