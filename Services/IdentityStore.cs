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
    class UserInfos
    {
        public readonly Dictionary<string, string> Keys = new();

        public readonly HashSet<string> Roles = new();

        public readonly List<UserLoginInfo> Logins = new();

        public readonly List<Claim> Claims = new();
    }

    public class IdentityStore : IIdentityStore
    {
        private readonly Dictionary<ApplicationUser, UserInfos> _users = new();

        private readonly List<ApplicationRole> _roles = new();

        // Users

        public Task<IdentityResult> CreateUserAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _users.Add(user, new UserInfos());

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteUserAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _users.Remove(user);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateUserAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<ApplicationUser?> FindUserByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(_users.Keys.Where(user => user.NormalizedUserName == normalizedUserName).FirstOrDefault());
        }

        public Task<ApplicationUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(_users.Keys.Where(user => user.Id == userId).FirstOrDefault());
        }

        public Task<ApplicationUser?> FindUserByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(_users.Keys.Where(user => user.NormalizedEmail == normalizedEmail).FirstOrDefault());
        }

        // Roles

        public Task<IdentityResult> CreateRoleAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _roles.Add(role);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteRoleAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _roles.RemoveAll(r => r.NormalizedName == role.NormalizedName);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateRoleAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<ApplicationRole?> FindRoleByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(_roles.Where(role => role.Id == roleId).SingleOrDefault());
        }

        public Task<ApplicationRole?> FindRoleByNameAsync(string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(_roles.Where(role => role.NormalizedName == normalizedName).SingleOrDefault());
        }

        public Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Roles.Add(roleName);

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Roles.Remove(roleName);

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                return Task.FromResult<IList<string>>(userInfos.Roles.ToList());
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                return Task.FromResult(userInfos.Roles.Contains(roleName));
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            List<ApplicationUser> users = new();

            foreach (var pair in _users)
            {
                if (pair.Value.Roles.Contains(roleName))
                {
                    users.Add(pair.Key);
                }
            }

            return Task.FromResult<IList<ApplicationUser>>(users);
        }

        // Tokens

        public Task SetTokenAsync(ApplicationUser user, string key, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Keys[key] = value;

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<string?> GetTokenAsync(ApplicationUser user, string key, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                if (userInfos.Keys.TryGetValue(key, out var value))
                {
                    return Task.FromResult<string?>(value);
                }
                else
                {
                    return Task.FromResult<string?>(null);
                }
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        // Logins

        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Logins.Add(new UserLoginInfo(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName));
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }

            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Logins.RemoveAll(login => login.LoginProvider == loginProvider && login.ProviderKey == providerKey);
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }

            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_users.TryGetValue(user, out var userInfos))
            {
                return Task.FromResult<IList<UserLoginInfo>>(userInfos.Logins);
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<ApplicationUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var pair in _users)
            {
                foreach (var login in pair.Value.Logins)
                {
                    if (login.LoginProvider == loginProvider && login.ProviderKey == providerKey)
                    {
                        return Task.FromResult<ApplicationUser?>(pair.Key);
                    }
                }
            }

            return Task.FromResult<ApplicationUser?>(null);
        }

        // Claims

        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            if (_users.TryGetValue(user, out var userInfos))
            {
                return Task.FromResult<IList<Claim>>(userInfos.Claims);
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Claims.AddRange(claims);

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        private static bool EqualClaims(Claim a, Claim b)
        {
            return a.Type == b.Type && a.Value == b.Value;
        }

        public Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Claims.RemoveAll(c => EqualClaims(c, claim));
                userInfos.Claims.Add(newClaim);

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (_users.TryGetValue(user, out var userInfos))
            {
                userInfos.Claims.RemoveAll(claim => claims.Select(c => EqualClaims(c, claim)).Any());

                return Task.CompletedTask;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(user));
            }
        }

        public Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            List<ApplicationUser> users = new();

            foreach (var pair in _users)
            {
                foreach (var c in pair.Value.Claims)
                {
                    if (EqualClaims(c, claim))
                    {
                        users.Add(pair.Key);
                        break;
                    }
                }
            }

            return Task.FromResult<IList<ApplicationUser>>(users);
        }
    }
}
