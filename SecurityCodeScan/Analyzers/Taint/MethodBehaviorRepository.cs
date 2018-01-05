using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using YamlDotNet.RepresentationModel;

namespace SecurityCodeScan.Analyzers.Taint
{
    public class MethodBehaviorRepository
    {
        private readonly Dictionary<string, MethodBehavior> MethodInjectableArguments = new Dictionary<string, MethodBehavior>();

        private readonly Dictionary<string, DiagnosticDescriptor> Descriptors = new Dictionary<string, DiagnosticDescriptor>();

        public void LoadConfiguration(string configurationFile)
        {
            var assembly = typeof(MethodBehaviorRepository).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream("SecurityCodeScan.Config." + configurationFile))
            using (var reader = new StreamReader(stream))
            {
                var yaml = new YamlStream();
                yaml.Load(reader);

                var mapping = (YamlMappingNode)yaml.Documents[0].RootNode;

                foreach (var entry in mapping.Children)
                {
                    var key   = (YamlScalarNode)entry.Key;

                    //The behavior structure allows the configuration of injectable arguments and password field
                    //This is the reason. The format merges the two concepts.

                    //Loading the properties for each entry
                    string beNamespace = GetField(entry, "namespace", true);
                    string beClassName = GetField(entry, "className", true);
                    string beMember    = GetField(entry, "member",    true);
                    string beName      = GetField(entry, "name",      true);

                    //--Method behavior
                    string beInjectableArguments = GetField(entry, "injectableArguments", defaultValue: "");
                    string bePasswordArguments   = GetField(entry, "passwordArguments",   defaultValue: "");
                    string beArgTypes            = GetField(entry, "argTypes");

                    //--Field behavior
                    bool beInjectableField = bool.Parse(GetField(entry, "injectableField", defaultValue: "false"));
                    bool bePasswordField   = bool.Parse(GetField(entry, "passwordField",   defaultValue: "false"));

                    //--Localization
                    string beLocale     = GetField(entry, "locale");
                    string beLocalePass = GetField(entry, "localePass");

                    string beTaintFromArguments = GetField(entry, "taintFromArguments", defaultValue: "");

                    //Converting the list of index to array
                    int[] argumentsIndexes          = ConvertToIntArray(beInjectableArguments.Split(','));
                    int[] passwordIndexes           = ConvertToIntArray(bePasswordArguments.Split(','));
                    int[] taintFromArgumentsIndexes = ConvertToIntArray(beTaintFromArguments.Split(','));

                    foreach (var locale in new[] { beLocale, beLocalePass })
                    {
                        if (locale != null && !Descriptors.ContainsKey(locale))
                        {
                            Descriptors.Add(locale, LocaleUtil.GetDescriptor(locale));
                        }
                    }

                    //Validate that 'argumentsIndexes' field 
                    if ((!beInjectableField && !bePasswordField) //Not a field signatures, arguments indexes is expected.
                        && argumentsIndexes.Length          == 0
                        && passwordIndexes.Length           == 0
                        && taintFromArgumentsIndexes.Length == 0)
                    {
                        throw new Exception($"The method behavior {key} is not missing injectableArguments or passwordArguments property");
                    }

                    //Injection based vulnerability
                    string globalKey = beArgTypes != null
                                           ? beNamespace + "." + beClassName + "|" + beName + "|" + beArgTypes
                                           :                                               //With arguments types discriminator
                                           beNamespace + "." + beClassName + "|" + beName; //Minimalist configuration

                    MethodInjectableArguments.Add(globalKey,
                                                  new MethodBehavior(argumentsIndexes,
                                                                     passwordIndexes,
                                                                     taintFromArgumentsIndexes,
                                                                     beLocale,
                                                                     beLocalePass,
                                                                     beInjectableField,
                                                                     bePasswordField));

                    //Logger.Log(beNamespace);
                }

                //Logger.Log(methodInjectableArguments.Count + " signatures loaded.");
            }
        }

        private string GetField(KeyValuePair<YamlNode, YamlNode> node,
                                string                           field,
                                bool                             mandatory    = false,
                                string                           defaultValue = null)
        {
            var nodeValue = (YamlMappingNode)node.Value;
            if (nodeValue.Children.TryGetValue(new YamlScalarNode(field), out var yamlNode))
            {
                return ((YamlScalarNode)yamlNode).Value;
            }

            if (mandatory)
                throw new Exception($"Unable to load the property {field} in node {node.Key}");

            return defaultValue;
        }

        public DiagnosticDescriptor[] GetDescriptors()
        {
            DiagnosticDescriptor[] descArray = new DiagnosticDescriptor[Descriptors.Count];
            Descriptors.Values.CopyTo(descArray, 0);
            return descArray;
        }

        /// <summary>
        /// Equivalent to : 
        /// <code>Array.ConvertAll(arrayString, int.Parse)</code>
        /// </summary>
        /// <param name="arrayStrings"></param>
        /// <returns></returns>
        private int[] ConvertToIntArray(string[] arrayStrings)
        {
            if (arrayStrings.Length == 1 && arrayStrings[0].Trim() == "")
                return new int[0];

            int[] newArray = new int[arrayStrings.Length];

            for (int i = 0; i < arrayStrings.Length; i++)
            {
                newArray[i] = int.Parse(arrayStrings[i]);
            }

            return newArray;
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

            string key = symbol.ContainingType + "|" + symbol.Name;

            if (MethodInjectableArguments.TryGetValue(key, out var behavior))
                return behavior;

            if (!symbol.ToString().Contains("("))
                return null;

            //Find a signature with parameter type discriminator
            string keyExtended = symbol.ContainingType.ContainingNamespace + "." +
                                 symbol.ContainingType.Name +
                                 "|" +
                                 symbol.Name +
                                 "|" +
                                 ExtractGenericParameterSignature(symbol);
            return MethodInjectableArguments.TryGetValue(keyExtended, out behavior) ? behavior : null;
        }

        private string ExtractGenericParameterSignature(ISymbol symbol)
        {
            // If not a method revert to the old method, just in case!
            if (symbol.Kind != SymbolKind.Method || !(symbol is IMethodSymbol))
            {
                Debug.WriteLine("Unexpected symbol type. " + symbol.ToString());
                var firstParenthese = symbol.ToString().IndexOf("(", StringComparison.Ordinal);
                return symbol.ToString().Substring(firstParenthese);
            }

            var    methodSymbol        = (IMethodSymbol)symbol;
            string result              = "(";
            bool   isFirstParameter    = true;
            var symbolDisplayFormat =
                new SymbolDisplayFormat(typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces);

            foreach (IParameterSymbol parameter in methodSymbol.Parameters)
            {
                if (isFirstParameter)
                {
                    isFirstParameter = false;
                }
                else
                {
                    result += ", ";
                }

                if (parameter.RefKind == RefKind.Out)
                {
                    result += "out ";
                }
                else if (parameter.RefKind == RefKind.Ref)
                {
                    result += "ref ";
                }

                string parameterTypeString = null;
                if (parameter.IsParams) // variable num arguments case
                {
                    result += "params ";
                    result += parameter.Type.ToDisplayString(symbolDisplayFormat).Replace("()", "[]");
                }
                else
                {
                    parameterTypeString = parameter.Type.ToDisplayString(symbolDisplayFormat);
                }

                result += parameterTypeString;

                if (parameter.HasExplicitDefaultValue && parameter.ExplicitDefaultValue != null)
                    result += " = " + parameter.ExplicitDefaultValue.ToString();
            }

            result += ")";
            Debug.WriteLine(symbol.ToString());
            Debug.WriteLine(result);
            return result;
        }

        private string GetFullTypeString(INamedTypeSymbol type)
        {
            string result = type.Name + GetTypeArgsStr(type, symbol => ((INamedTypeSymbol)symbol).TypeArguments);
            return result;
        }

        private string GetTypeArgsStr(ISymbol                                    symbol,
                                      Func<ISymbol, ImmutableArray<ITypeSymbol>> typeArgGetter)
        {
            IEnumerable<ITypeSymbol> typeArgs = typeArgGetter(symbol);

            string result = "";

            if (typeArgs.Any())
            {
                result += "<";

                bool isFirstIteration = true;
                foreach (ITypeSymbol typeArg in typeArgs)
                {
                    // insert comma if not first iteration
                    if (isFirstIteration)
                    {
                        isFirstIteration = false;
                    }
                    else
                    {
                        result += ", ";
                    }

                    string strToAdd;
                    if (typeArg is ITypeParameterSymbol typeParameterSymbol)
                    {
                        // this is a generic argument
                        strToAdd = typeParameterSymbol.Name;
                    }
                    else
                    {
                        // this is a generic argument value. 
                        var namedTypeSymbol = typeArg as INamedTypeSymbol;

                        strToAdd = GetFullTypeString(namedTypeSymbol);
                    }

                    result += strToAdd;
                }

                result += ">";
            }

            Debug.WriteLine(symbol.ToString());
            Debug.WriteLine(result);
            return result;
        }
    }
}
