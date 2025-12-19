namespace ProyectoFinalTecWeb.Entities.Dtos.Auth
{
    public class LoginResponseDto
    {
        public required UserDto User { get; set; }
        public required string Role { get; set; }
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; }
    }

    public class UserDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }
    public class RefreshRequestDto
    { 
        public required string RefreshToken {  get; set; }
    }

    public class ForgotPasswordDto
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ResetPasswordDto
    {
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }


}
