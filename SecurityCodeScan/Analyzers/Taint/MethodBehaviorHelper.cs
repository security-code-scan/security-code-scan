using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    internal static class MethodBehaviorHelper
    {
        public static string GetMethodBehaviorKey(string nameSpace, string className, string name, string argTypes)
        {
            if (string.IsNullOrWhiteSpace(className))
                throw new ArgumentException("ClassName");

            string key;                       
            if (argTypes != null)
            {
                if (string.IsNullOrWhiteSpace(name))
                    throw new ArgumentException("Name");

                key = $"{nameSpace}.{className}|{name}|{argTypes}";
            }
            else if (name != null)
            {
                key = $"{nameSpace}.{className}|{name}";
            }
            else
            {
                key = $"{nameSpace}.{className}";
            }

            return key;
        }

        private const string VbIndexerName = "Item";
        private const string CsIndexerName = "this[]";

        /// <summary>
        /// Get the method behavior for a given symbol
        /// </summary>
        public static MethodBehavior GetMethodBehavior(this ISymbol symbol, IReadOnlyDictionary<string, MethodBehavior> injectableArguments)
        {
            var name = symbol.Name == VbIndexerName && symbol.Language == LanguageNames.VisualBasic ? CsIndexerName : symbol.Name;
            string nameSpaceWithClass = null;

            // First try to find specific overload
            if (symbol is IMethodSymbol methodSymbol)
            {
                nameSpaceWithClass = $"{symbol.ContainingType.ContainingNamespace.GetTypeName()}.{symbol.ContainingType.Name}";
                var keyExtended = $"{nameSpaceWithClass}|{name}|{ExtractGenericParameterSignature(methodSymbol)}";

                if (injectableArguments.TryGetValue(keyExtended, out var behavior1))
                    return behavior1;
            }

            if (symbol.ContainingType == null)
                return null;

            if (nameSpaceWithClass == null)
                nameSpaceWithClass = $"{symbol.ContainingType.ContainingNamespace.GetTypeName()}.{symbol.ContainingType.Name}";

            // try to find generic rule by method name
            string key = $"{nameSpaceWithClass}|{name}";
            if (injectableArguments.TryGetValue(key, out var behavior2))
                return behavior2;

            // try to find generic rule by containing type name
            key = nameSpaceWithClass;
            if (injectableArguments.TryGetValue(key, out var behavior3))
                return behavior3;

            return null;
        }

        private static readonly SymbolDisplayFormat MethodFormat = new SymbolDisplayFormat(
            typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
            memberOptions:          SymbolDisplayMemberOptions.IncludeParameters,
            extensionMethodStyle:   SymbolDisplayExtensionMethodStyle.StaticMethod,
            parameterOptions:       SymbolDisplayParameterOptions.IncludeParamsRefOut |
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
                methodSignature = methodSignature.Replace("ByRef ", "out ");
            }

            return methodSignature;
        }
    }
}
