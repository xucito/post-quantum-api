
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PostQuantum.API.Modules.Users
{
    public class User: IdentityUser<Guid>
    {
        public byte[]? PublicKey { get; set; }
        public DateTime ModifiedOn { get; set; }
        public DateTime CreatedOn { get; set; }
        public string Name { get; set; }
    }
}
