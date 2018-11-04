using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    internal static class MethodBehaviorHelper
    {
        private static Dictionary<string, MethodBehavior> GetMethodInjectableArguments(ImmutableArray<AdditionalText> additionalFiles)
        {
            return ConfigurationManager.Instance.GetBehaviors(additionalFiles).ToDictionary(pair => pair.Key, pair => pair.Value);
        }

        /// <summary>
        /// Get the method behavior for a given symbol
        /// </summary>
        /// <param name="additionalFiles"></param>
        /// <param name="symbol"></param>
        /// <returns></returns>
        public static MethodBehavior GetMethodBehavior(this ISymbol symbol, ImmutableArray<AdditionalText> additionalFiles)
        {
            var injectableArguments = GetMethodInjectableArguments(additionalFiles);
            // First try to find specific overload
            if (symbol.ToString().Contains("("))
            {
                string keyExtended =
                    $"{symbol.ContainingType.ContainingNamespace}.{symbol.ContainingType.Name}|{symbol.Name}|{ExtractGenericParameterSignature((IMethodSymbol)symbol)}";

                if (injectableArguments.TryGetValue(keyExtended, out var behavior1))
                    return behavior1;
            }

            // try to find generic rule by method name
            string key = $"{symbol.ContainingType.GetTypeName()}|{symbol.Name}";

            if (injectableArguments.TryGetValue(key, out var behavior2))
                return behavior2;

            return null;
        }

        private static readonly SymbolDisplayFormat MethodFormat = new SymbolDisplayFormat(
            typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
            memberOptions: SymbolDisplayMemberOptions.IncludeParameters,
            extensionMethodStyle: SymbolDisplayExtensionMethodStyle.StaticMethod,
            parameterOptions: SymbolDisplayParameterOptions.IncludeParamsRefOut |
                              SymbolDisplayParameterOptions.IncludeType);

        private static string ExtractGenericParameterSignature(IMethodSymbol methodSymbol)
        {
            var methodSignature = methodSymbol.ToDisplayString(MethodFormat);
            methodSignature = methodSignature.Substring(methodSignature.IndexOf('('));
            if (methodSymbol.Language == LanguageNames.VisualBasic)
            {
                if (methodSignature != "()")
                    methodSignature = methodSignature.Replace("()", "[]");

                methodSignature = methodSignature.Replace("ParamArray ", "params ");
            }

            return methodSignature;
        }
    }
}
