using System.Resources;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Locale
{
    public class LocaleUtil
    {
        private static YamlResourceManager ResourceManager;

        public static DiagnosticDescriptor GetDescriptor(string id, string titleId = "title", string[] args = null)
        {
            var localTitle = GetLocalString($"{id}_{titleId}");
            var localDesc  = GetLocalString($"{id}_description");
            return new DiagnosticDescriptor(id,
                                            localTitle,
                                            localTitle,
                                            "Security",
                                            DiagnosticSeverity.Warning,
                                            isEnabledByDefault: true,
                                            helpLinkUri: "https://security-code-scan.github.io/#" + id,
                                            description: args == null ?
                                                             localDesc :
                                                             string.Format(localDesc.ToString(), args)
            );
        }

        private static LocalizableString GetLocalString(string id)
        {
            return new LocalizableResourceString(id, GetResourceManager(), typeof(LocaleUtil));
        }

        private static ResourceManager GetResourceManager()
        {
            if (ResourceManager != null)
                return ResourceManager;

            ResourceManager = new YamlResourceManager();
            ResourceManager.Load();

            return ResourceManager;
        }
    }
}
