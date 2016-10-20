using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public class MethodBehavior
    {
        public int[] injectablesArguments { get; }
        public string vulnerabilityLocale { get; }
        
        public MethodBehavior(int[] injectablesArguments, string vulnerabilityLocale) {
            this.injectablesArguments = injectablesArguments;
            this.vulnerabilityLocale = vulnerabilityLocale;
        }


    }
}
