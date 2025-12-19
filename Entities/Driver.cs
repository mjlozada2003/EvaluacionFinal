using System.Threading.Tasks;

namespace ProyectoFinalTecWeb.Entities
{
    public class Driver
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = default!;
        public string Licence { get; set; } = default!;
        public string Phone { get; set; } = default!;
        public string Email { get; set; } = string.Empty;

        // N:M Driver -> Vehicle
        public ICollection<Vehicle> Vehicles { get; set; } = new List<Vehicle>();

        // 1:M driver -> trip
        public ICollection<Trip> Trips { get; set; } = new List<Trip>();

        // Auth Verification
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "Driver"; //"Passenger" | "Driver"
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiresAt { get; set; }
        public DateTime? RefreshTokenRevokedAt { get; set; }
        public string? CurrentJwtId { get; set; }

    }
}
