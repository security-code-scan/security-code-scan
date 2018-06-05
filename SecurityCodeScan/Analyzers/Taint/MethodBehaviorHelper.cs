using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    public static class MethodBehaviorHelper
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
            if (symbol == null)
            {
                //The symbol was not properly resolved
                return null;
            }

            // First try to find specific overload
            if (symbol.ToString().Contains("("))
            {
                string keyExtended =
                    $"{symbol.ContainingType.ContainingNamespace}.{symbol.ContainingType.Name}|{symbol.Name}|{ExtractGenericParameterSignature(symbol)}";
                if (GetMethodInjectableArguments(additionalFiles).TryGetValue(keyExtended, out var behavior1))
                    return behavior1;
            }

            // try to find generic rule by method name
            string key = $"{symbol.ContainingType.GetTypeName()}|{symbol.Name}";

            if (GetMethodInjectableArguments(additionalFiles).TryGetValue(key, out var behavior2))
                return behavior2;

            return null;
        }

        private static string ExtractGenericParameterSignature(ISymbol symbol)
        {
            // If not a method revert to the old method, just in case!
            if (symbol.Kind != SymbolKind.Method || !(symbol is IMethodSymbol))
            {
                Debug.WriteLine($"Unexpected symbol type. {symbol}");
                var firstParenthese = symbol.ToString().IndexOf("(", StringComparison.Ordinal);
                return symbol.ToString().Substring(firstParenthese);
            }

            var    methodSymbol        = (IMethodSymbol)symbol;
            var result = new StringBuilder("(", 200);
            bool   isFirstParameter    = true;

            foreach (IParameterSymbol parameter in methodSymbol.Parameters)
            {
                if (isFirstParameter)
                {
                    isFirstParameter = false;
                }
                else
                {
                    result.Append(", ");
                }

                switch (parameter.RefKind)
                {
                    case RefKind.Out:
                        result.Append("out ");
                        break;
                    case RefKind.Ref:
                        result.Append("ref ");
                        break;
                }

                string parameterTypeString = null;
                if (parameter.IsParams) // variable num arguments case
                {
                    result.Append("params ");
                    result.Append(parameter.Type.GetTypeName().Replace("()", "[]"));
                }
                else
                {
                    parameterTypeString = parameter.Type.GetTypeName();
                    if (parameter.Type.Kind == SymbolKind.ArrayType)
                        parameterTypeString = parameterTypeString.Replace("()", "[]");
                }

                result.Append(parameterTypeString);

                if (parameter.HasExplicitDefaultValue && parameter.ExplicitDefaultValue != null)
                    result.Append(" = ").Append(parameter.ExplicitDefaultValue);
            }

            result.Append(")");
            Debug.WriteLine(symbol.ToString());
            Debug.WriteLine(result);
            return result.ToString();
        }
    }
}
