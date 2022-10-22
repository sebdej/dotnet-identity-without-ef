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

using IdentityWithoutEF.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace IdentityWithoutEF.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public IList<string>? Roles { get; set; }
    public IList<Claim>? Claims { get; set; }
    public IList<UserLoginInfo>? Logins { get; set; }

    public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
}

    private async Task GetUserInfo()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user != null)
        {
            Roles = await _userManager.GetRolesAsync(user);
            Claims = await _userManager.GetClaimsAsync(user);
            Logins = await _userManager.GetLoginsAsync(user);
        }
    }

    public async Task OnGetAsync()
    {
        await GetUserInfo();
    }

    public async Task OnPostAsync(string role)
    {
        var user = await _userManager.GetUserAsync(User);

        if (user != null)
        {
            await _userManager.AddToRoleAsync(user, role);

            await _signInManager.SignInAsync(user, false);
        }

        await GetUserInfo();
    }
}
