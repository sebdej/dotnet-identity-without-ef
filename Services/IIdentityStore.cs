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
using System.Security.Claims;

namespace IdentityWithoutEF.Services
{
    public interface IIdentityStore
    {
        // Users

        Task<IdentityResult> CreateUserAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task<IdentityResult> DeleteUserAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task<IdentityResult> UpdateUserAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task<ApplicationUser?> FindUserByNameAsync(string normalizedUserName, CancellationToken cancellationToken);

        Task<ApplicationUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken);

        Task<ApplicationUser?> FindUserByEmailAsync(string normalizedEmail, CancellationToken cancellationToken);

        // Roles

        Task<IdentityResult> CreateRoleAsync(ApplicationRole role, CancellationToken cancellationToken);

        Task<IdentityResult> DeleteRoleAsync(ApplicationRole role, CancellationToken cancellationToken);

        Task<IdentityResult> UpdateRoleAsync(ApplicationRole role, CancellationToken cancellationToken);

        Task<ApplicationRole?> FindRoleByIdAsync(string roleId, CancellationToken cancellationToken);

        Task<ApplicationRole?> FindRoleByNameAsync(string normalizedName, CancellationToken cancellationToken);

        Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken);

        Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken);

        Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken);

        Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken);

        // Tokens

        Task SetTokenAsync(ApplicationUser user, string key, string value, CancellationToken cancellationToken);

        Task<string?> GetTokenAsync(ApplicationUser user, string key, CancellationToken cancellationToken);

        // Logins

        Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken);

        Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken);

        Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task<ApplicationUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken);

        // Claims

        Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken);

        Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken);

        Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken);
    }
}
