namespace ProyectoFinalTecWeb.Entities
{
    public class Passenger
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = default!;
        public string Phone { get; set; } = default!;
        public string Email { get; set; } = string.Empty;
        // 1:N Passenger -> Trips
        public ICollection<Trip> Trips { get; set; } = new List<Trip>();

        // Auth Verification
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "Passenger"; //"Passenger" | "Driver"
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiresAt { get; set; }
        public DateTime? RefreshTokenRevokedAt { get; set; }
        public string? CurrentJwtId { get; set; }

    }
}
