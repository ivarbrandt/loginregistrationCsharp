using Microsoft.EntityFrameworkCore;

namespace loginandreg.Models
{
    public class MyContext : DbContext
    {
        public MyContext(DbContextOptions options) : base(options) {}
        public DbSet<User> Users { get; set;}
    }
}