using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Locale
{
    internal class LocaleUtil
    {
        private static YamlResourceManager ResourceManager => ResourceManagerCached.Value;
        private static readonly Lazy<YamlResourceManager> ResourceManagerCached = new Lazy<YamlResourceManager>(() =>
                                                                                                                {
                                                                                                                    var m = new YamlResourceManager();
                                                                                                                    m.Load();
                                                                                                                    return m;
                                                                                                                });

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
            var localeIds = ResourceManager.LocaleKeyIds;
            return localeIds.Select(localeId => GetDescriptor(localeId));
        }

        private static LocalizableString GetLocalString(string id)
        {
            return new LocalizableResourceString(id, ResourceManager, typeof(LocaleUtil));
        }
    }
}
