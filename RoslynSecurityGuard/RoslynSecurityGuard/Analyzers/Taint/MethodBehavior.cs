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
        public int[] taintFromArguments { get; }
        public string localeInjection { get; }
        public string localePassword { get; }
        public bool isInjectableField { get; }
        public bool isPasswordField { get; }
        
        public MethodBehavior(int[] injectablesArguments, int[] passwordArguments, int[] taintFromArguments, string localeInjection, string localePassword, 
            bool isInjectableField, bool isPasswordField) {

            this.injectablesArguments = injectablesArguments;
            this.passwordArguments = passwordArguments;
            this.taintFromArguments = taintFromArguments;
            this.localeInjection = localeInjection;
            this.localePassword = localePassword;
            this.isInjectableField = isInjectableField;
            this.isPasswordField = isPasswordField;

        }


    }
}
