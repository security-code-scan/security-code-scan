using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;

namespace SecurityCodeScan.Analyzers.Locale
{
    public class LocaleUtil
    {
        private static YamlResourceManager ResourceManager = null;

        public static DiagnosticDescriptor GetDescriptor(string id, string[] args = null)
        {


            var localTitle = GetLocalString(id + "_Title");
            var localDesc = GetLocalString(id + "_Description");
            return new DiagnosticDescriptor(id,
                localTitle,
                localTitle,
                "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true,
                helpLinkUri: "https://security-code-scan.github.io/#" + id,
                description: (args == null ? localDesc : string.Format(localDesc.ToString(), args))
                );
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
