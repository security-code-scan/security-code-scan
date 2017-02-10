using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public enum VariableTaint
    {
        /// <summary>
        /// Constant string
        /// </summary>
        CONSTANT,
        /// <summary>
        /// Value that are safe to use
        /// </summary>
        SAFE,
        /// <summary>
        /// Value obtain from an external sources
        /// </summary>
        UNKNOWN,
        /// <summary>
        /// Value taken from input source.
        /// </summary>
        TAINTED
    }
}
