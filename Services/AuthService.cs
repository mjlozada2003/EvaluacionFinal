using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ProyectoFinalTecWeb.Entities;
using ProyectoFinalTecWeb.Entities.Dtos.Auth;
using ProyectoFinalTecWeb.Entities.Dtos.DriverDto;
using ProyectoFinalTecWeb.Entities.Dtos.PassengerDto;
using ProyectoFinalTecWeb.Repositories;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ProyectoFinalTecWeb.Services
{
    public class AuthService : IAuthService
    {
        private readonly IDriverRepository _drivers;
        private readonly IPassengerRepository _passengers;
        private readonly IConfiguration _configuration;
        private static readonly ConcurrentDictionary<string, PasswordResetInfo> _resetTokens = new();

        public AuthService(IDriverRepository drivers, IPassengerRepository passengers, IConfiguration configuration)
        {
            _drivers = drivers;
            _passengers = passengers;
            _configuration = configuration;
        }

        public async Task<(bool ok, LoginResponseDto? response)> LoginAsync(LoginDto dto)
        {
            // Primero buscar driver
            var driver = await _drivers.GetByEmailAddress(dto.Email);
            if (driver != null)
            {
                var ok = BCrypt.Net.BCrypt.Verify(dto.Password, driver.PasswordHash);
                if (!ok) return (false, null);

                // Generar par access/refresh
                var (accessToken, expiresIn, jti) = GenerateJwtTokenD(driver);
                var refreshToken = GenerateSecureRefreshToken();

                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                driver.RefreshToken = refreshToken;
                driver.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                driver.RefreshTokenRevokedAt = null;
                driver.CurrentJwtId = jti;
                await _drivers.Update(driver);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = driver.Id, Name = driver.Name, Email = driver.Email },
                    Role = driver.Role,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Si no es driver, buscar passenger
            var passenger = await _passengers.GetByEmailAddress(dto.Email);
            if (passenger != null)
            {
                var ok = BCrypt.Net.BCrypt.Verify(dto.Password, passenger.PasswordHash);
                if (!ok) return (false, null);

                // Generar par access/refresh
                var (accessToken, expiresIn, jti) = GenerateJwtTokenP(passenger);
                var refreshToken = GenerateSecureRefreshToken();

                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                passenger.RefreshToken = refreshToken;
                passenger.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                passenger.RefreshTokenRevokedAt = null;
                passenger.CurrentJwtId = jti;
                await _passengers.Update(passenger);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = passenger.Id, Name = passenger.Name, Email = passenger.Email },
                    Role = passenger.Role,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Si no es ni driver ni passenger
            return (false, null);
        }

        public async Task<(bool ok, LoginResponseDto? response)> RefreshAsync(RefreshRequestDto dto)
        {
            // Buscar driver con el refresh token
            var driver = await _drivers.GetByRefreshToken(dto.RefreshToken);
            if (driver != null)
            {
                // Validaciones de refresh
                if (driver.RefreshToken != dto.RefreshToken) return (false, null);
                if (driver.RefreshTokenRevokedAt.HasValue) return (false, null);
                if (!driver.RefreshTokenExpiresAt.HasValue || driver.RefreshTokenExpiresAt.Value < DateTime.UtcNow) return (false, null);

                // Rotación: generar nuevo access + refresh y revocar el anterior
                var (accessToken, expiresIn, jti) = GenerateJwtTokenD(driver);
                var newRefresh = GenerateSecureRefreshToken();
                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                driver.RefreshToken = newRefresh;
                driver.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                driver.RefreshTokenRevokedAt = null; // seguimos activo
                driver.CurrentJwtId = jti;
                await _drivers.Update(driver);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = driver.Id, Name = driver.Name, Email = driver.Email },
                    Role = driver.Role,
                    AccessToken = accessToken,
                    RefreshToken = newRefresh,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Buscar passenger con el refresh token
            var passenger = await _passengers.GetByRefreshToken(dto.RefreshToken);
            if (passenger != null)
            {
                // Validaciones de refresh
                if (passenger.RefreshToken != dto.RefreshToken) return (false, null);
                if (passenger.RefreshTokenRevokedAt.HasValue) return (false, null);
                if (!passenger.RefreshTokenExpiresAt.HasValue || passenger.RefreshTokenExpiresAt.Value < DateTime.UtcNow) return (false, null);

                // Rotación: generar nuevo access + refresh y revocar el anterior
                var (accessToken, expiresIn, jti) = GenerateJwtTokenP(passenger);
                var newRefresh = GenerateSecureRefreshToken();
                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                passenger.RefreshToken = newRefresh;
                passenger.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                passenger.RefreshTokenRevokedAt = null;
                passenger.CurrentJwtId = jti;
                await _passengers.Update(passenger);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = passenger.Id, Name = passenger.Name, Email = passenger.Email },
                    Role = passenger.Role,
                    AccessToken = accessToken,
                    RefreshToken = newRefresh,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            return (false, null);
        }

        public async Task<string> RegisterDriverAsync(RegisterDriverDto dto)
        {
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            var driver = new Driver
            {
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Name = dto.Name,
                Role = dto.Role,
                Licence = dto.Licence,
                Phone = dto.Phone
            };
            await _drivers.AddAsync(driver);
            return driver.Id.ToString();
        }

        public async Task<string> RegisterPassengerAsync(RegisterPassengerDto dto)
        {
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            var passenger = new Passenger
            {
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Name = dto.Name,
                Phone = dto.Phone,
                Role = dto.Role
            };
            await _passengers.AddAsync(passenger);
            return passenger.Id.ToString();
        }

        private (string token, int expiresInSeconds, string jti) GenerateJwtTokenD(Driver driver)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var key = jwtSection["Key"]!;
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expireMinutes = int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, driver.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, driver.Email),
                new Claim(ClaimTypes.Name, driver.Name),
                new Claim(ClaimTypes.Role, driver.Role),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
            };

            var keyBytes = Convert.FromBase64String(key);
            var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return (jwt, (int)TimeSpan.FromMinutes(expireMinutes).TotalSeconds, jti);
        }

        private (string token, int expiresInSeconds, string jti) GenerateJwtTokenP(Passenger passenger)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var key = jwtSection["Key"]!;
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expireMinutes = int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, passenger.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, passenger.Email),
                new Claim(ClaimTypes.Name, passenger.Name),
                new Claim(ClaimTypes.Role, passenger.Role),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
            };

            var keyBytes = Convert.FromBase64String(key);
            var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return (jwt, (int)TimeSpan.FromMinutes(expireMinutes).TotalSeconds, jti);
        }

        private static string GenerateSecureRefreshToken()
        {
            // 64 bytes aleatorios en Base64Url
            var bytes = RandomNumberGenerator.GetBytes(64);
            return Base64UrlEncoder.Encode(bytes);
        }

        public async Task<(bool ok, string token)> ForgotPasswordAsync(ForgotPasswordDto dto)
        {
         
            var driver = await _drivers.GetByEmailAddress(dto.Email);
            var passenger = await _passengers.GetByEmailAddress(dto.Email);

            if (driver == null && passenger == null) return (false, string.Empty);

            //Generar token: Minutos transcurridos del día
            var now = DateTime.Now;
            int minutesToken = (now.Hour * 60) + now.Minute;
            string tokenString = minutesToken.ToString();

            var resetInfo = new PasswordResetInfo
            {
                Email = dto.Email,
                CreatedAt = DateTime.UtcNow
            };

            _resetTokens[tokenString] = resetInfo;

            return (true, tokenString);
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordDto dto)
        {

            if (!_resetTokens.TryGetValue(dto.Token, out var info))
                return false; 

            //Validar tiempo: máximo 15 minutos
            var timeElapsed = DateTime.UtcNow - info.CreatedAt;
            if (timeElapsed.TotalMinutes > 15)
            {
                _resetTokens.TryRemove(dto.Token, out _);
                return false;
            }

            //Buscar al usuario por el email guardado en el token
            var driver = await _drivers.GetByEmailAddress(info.Email);
            var passenger = await _passengers.GetByEmailAddress(info.Email);

            string newHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);

            //Actualizar password 
            if (driver != null)
            {
                driver.PasswordHash = newHash;
                await _drivers.Update(driver);
            }
            else if (passenger != null)
            {
                passenger.PasswordHash = newHash;
                await _passengers.Update(passenger);
            }
            else return false;

            _resetTokens.TryRemove(dto.Token, out _);

            return true;
        }

    }
}
