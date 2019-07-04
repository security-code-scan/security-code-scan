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

            string nameSpacePrefix = string.IsNullOrWhiteSpace(nameSpace) ? "" : $"{nameSpace}.";

            string key;
            if (argTypes != null)
            {
                if (string.IsNullOrWhiteSpace(name))
                    throw new ArgumentException("Name");

                key = $"{nameSpacePrefix}{className}|{name}|{argTypes}";
            }
            else if (name != null)
            {
                key = $"{nameSpacePrefix}{className}|{name}";
            }
            else
            {
                key = $"{nameSpacePrefix}{className}";
            }

            return key;
        }

        public static bool IsTaintEntryPoint(this ISymbol symbol, ReadOnlyHashSet<string> entryPoints)
        {
            if (symbol.ContainingType == null)
                return false;

            var nameSpace = symbol.ContainingType.ContainingNamespace.GetTypeName();

            // first search for method name
            string key = string.IsNullOrWhiteSpace(nameSpace)
                             ? $"{symbol.ContainingType.Name}|{symbol.Name}"
                             : $"{nameSpace}.{symbol.ContainingType.Name}|{symbol.Name}";
            if (entryPoints.Contains(key))
                return true;

            if (symbol.IsPublic() && !symbol.IsConstructor()) // todo: attributes + filter NonAction
            {
                var containingType = symbol.ContainingType;
                if (containingType.IsTypeOrDerivedFrom(entryPoints))
                    return true;
            }

            return false;
        }

        public static bool IsTaintType(this ITypeSymbol symbol, IReadOnlyDictionary<string, MethodBehavior> behaviors)
        {
            string key = symbol.GetTypeName();
            if (!behaviors.TryGetValue(key, out var behavior))
                return false;

            if (behavior.PostConditions.TryGetValue((int)ArgumentIndex.Returns, out PostCondition postCondition))
                return postCondition.Taint == (uint)VariableTaint.Tainted;

            return false;
        }

        private const string VbIndexerName = "Item";
        private const string CsIndexerName = "this[]";

        /// <summary>
        /// Get the method behavior for a given symbol
        /// </summary>
        public static MethodBehavior GetMethodBehavior(this ISymbol symbol, IReadOnlyDictionary<string, MethodBehavior> behaviors)
        {
            var name = symbol.Name == VbIndexerName && symbol.Language == LanguageNames.VisualBasic ? CsIndexerName : symbol.Name;
            string nameSpaceWithClass = null;

            string GetNameSpaceWithClass()
            {
                var nameSpace = symbol.ContainingType.ContainingNamespace.GetTypeName();
                return string.IsNullOrWhiteSpace(nameSpace) ? symbol.ContainingType.Name : $"{nameSpace}.{symbol.ContainingType.Name}";
            }

            // First try to find specific overload
            if (symbol is IMethodSymbol methodSymbol)
            {
                nameSpaceWithClass = GetNameSpaceWithClass();
                var keyExtended = $"{nameSpaceWithClass}|{name}|{ExtractGenericParameterSignature(methodSymbol)}";

                if (behaviors.TryGetValue(keyExtended, out var behavior1))
                    return behavior1;
            }

            if (symbol.ContainingType == null)
                return null;

            if (nameSpaceWithClass == null)
                nameSpaceWithClass = GetNameSpaceWithClass();

            // try to find generic rule by method name
            string key = $"{nameSpaceWithClass}|{name}";
            if (behaviors.TryGetValue(key, out var behavior2))
                return behavior2;

            // try to find generic rule by containing type name
            key = nameSpaceWithClass;
            if (behaviors.TryGetValue(key, out var behavior3))
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
            var firstParenthesis = methodSignature.IndexOf('(');
            if (firstParenthesis == -1)
            {
                // some weird COM interop indexers are treated as methods
                // for example:
                // [Guid("04A72314-32E9-48E2-9B87-A63603454F3E")]
                // [TypeLibType(4160)]
                // [ComImport]
                // public interface _DTE
                // ...
                //      [DispId(212)]
                //      [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                //      [return: MarshalAs(UnmanagedType.Interface)]
                //      Properties get_Properties([MarshalAs(UnmanagedType.BStr)] string Category, [MarshalAs(UnmanagedType.BStr)] string Page);
                return string.Empty;
            }

            methodSignature = methodSignature.Substring(firstParenthesis);
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
