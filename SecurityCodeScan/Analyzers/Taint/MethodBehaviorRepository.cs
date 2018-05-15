using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using YamlDotNet.RepresentationModel;

namespace SecurityCodeScan.Analyzers.Taint
{
    public class MethodBehaviorRepository
    {
        private readonly Dictionary<string, MethodBehavior> MethodInjectableArguments = new Dictionary<string, MethodBehavior>();

        private readonly Dictionary<string, DiagnosticDescriptor> Descriptors = new Dictionary<string, DiagnosticDescriptor>();

        public void LoadConfiguration()
        {
            var behaviorInfos = Configuration.GetBehaviors();

            foreach (var info in behaviorInfos)
            {
                foreach (var locale in new[] { info.Locale, info.LocalePass })
                {
                    if (locale != null && !Descriptors.ContainsKey(locale))
                    {
                        Descriptors.Add(locale, LocaleUtil.GetDescriptor(locale));
                    }
                }

                string key = info.ArgTypes != null ? $"{info.Namespace}.{info.ClassName}|{info.Name}|{info.ArgTypes}" : //With arguments types discriminator
                                                     $"{info.Namespace}.{info.ClassName}|{info.Name}"; //Minimalist configuration

                MethodInjectableArguments.Add(key, new MethodBehavior(info.InjectableArguments,
                                                      info.PasswordArguments,
                                                      info.TaintFromArguments,
                                                      info.Locale,
                                                      info.LocalePass,
                                                      info.InjectableField,
                                                      info.IsPasswordField));
            }
        }

        public DiagnosticDescriptor[] GetDescriptors()
        {
            DiagnosticDescriptor[] descArray = new DiagnosticDescriptor[Descriptors.Count];
            Descriptors.Values.CopyTo(descArray, 0);
            return descArray;
        }

        /// <summary>
        /// Get the method behavior for a given symbol
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        public MethodBehavior GetMethodBehavior(ISymbol symbol)
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
                if (MethodInjectableArguments.TryGetValue(keyExtended, out var behavior1))
                    return behavior1;
            }

            // try to find generic rule by method name
            string key = $"{symbol.ContainingType.GetTypeName()}|{symbol.Name}";

            if (MethodInjectableArguments.TryGetValue(key, out var behavior2))
                return behavior2;

            return null;
        }

        private string ExtractGenericParameterSignature(ISymbol symbol)
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
