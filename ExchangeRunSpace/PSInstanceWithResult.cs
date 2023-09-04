using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace ExchangeRunSpace
{
    public class PSInstanceWithResult
    {
        public PowerShell PowerShell { get; set; }
        public IAsyncResult PSInstanceResult { get; set; }
        public long ExecutionTime { get; set; } = -1;
    }
}
