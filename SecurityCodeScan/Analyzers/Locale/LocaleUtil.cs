using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Locale
{
    internal class LocaleUtil
    {
        private static volatile YamlResourceManager ResourceManager;

        public static DiagnosticDescriptor GetDescriptor(string id, string titleId = "title", string descriptionId = "description", string[] args = null)
        {
            var localTitle = GetLocalString($"{id}_{titleId}");
            var localDesc  = GetLocalString($"{id}_{descriptionId}");
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

        public static IEnumerable<DiagnosticDescriptor> GetAllAvailableDescriptors()
        {
            var localeIds = GetResourceManager().LocaleKeyIds;
            return localeIds.Select(localeId => GetDescriptor(localeId));
        }

        private static LocalizableString GetLocalString(string id)
        {
            return new LocalizableResourceString(id, GetResourceManager(), typeof(LocaleUtil));
        }

        private static readonly object ResourceManagerLock = new object();

        private static YamlResourceManager GetResourceManager()
        {
            if (ResourceManager != null)
                return ResourceManager;

            lock (ResourceManagerLock)
            {
                if (ResourceManager != null)
                    return ResourceManager;

                var resourceManager = new YamlResourceManager();
                resourceManager.Load();
                Thread.MemoryBarrier();
                ResourceManager = resourceManager;
            }

            return ResourceManager;
        }
    }
}
