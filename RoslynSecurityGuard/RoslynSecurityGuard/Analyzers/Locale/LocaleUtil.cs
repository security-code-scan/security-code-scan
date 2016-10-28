using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers.Locale
{
    public class LocaleUtil
    {
        private static YamlResourceManager ResourceManager = null;

        public static DiagnosticDescriptor GetDescriptor(string id)
        {
            var localTitle = GetLocalString(id + "_Title");
            return new DiagnosticDescriptor(id,
                localTitle,
                localTitle,
                "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true,
                helpLinkUri: "https://dotnet-security-guard.github.io/rules.htm#" + id,
                description: GetLocalString(id + "_Description"));
        }

        private static LocalizableString GetLocalString(string id)
        {
            return new LocalizableResourceString(id, GetResourceManager(), typeof(LocaleUtil)); 
            //return new LocalizableResourceString(id, Messages.ResourceManager, typeof(Messages));
        }

        private static ResourceManager GetResourceManager() {
            if (ResourceManager == null) {
                ResourceManager = new YamlResourceManager();
                ResourceManager.Load();
            }
            return ResourceManager;
        }
    }
}
