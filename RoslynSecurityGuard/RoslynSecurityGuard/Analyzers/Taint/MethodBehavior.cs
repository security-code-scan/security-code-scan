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
        public int[] passwordArguments { get; }
        public string vulnerabilityLocale { get; }
        
        public MethodBehavior(int[] injectablesArguments, int[] passwordArguments, string vulnerabilityLocale) {
            this.injectablesArguments = injectablesArguments;
            this.passwordArguments = passwordArguments;
            this.vulnerabilityLocale = vulnerabilityLocale;
        }


    }
}
