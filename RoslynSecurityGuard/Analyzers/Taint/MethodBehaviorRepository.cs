using Microsoft.CodeAnalysis;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using YamlDotNet.RepresentationModel;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public class MethodBehaviorRepository
    {
        private Dictionary<string, MethodBehavior> methodInjectableArguments = new Dictionary<string, MethodBehavior>();

        private Dictionary<string, DiagnosticDescriptor> descriptors = new Dictionary<string, DiagnosticDescriptor>();

        public void LoadConfiguration(string configurationFile)
        {
            var assembly = typeof(MethodBehaviorRepository).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream("RoslynSecurityGuard.Config." + configurationFile))
            using (StreamReader reader = new StreamReader(stream))
            {
                var yaml = new YamlStream();
                yaml.Load(reader);

                var mapping = (YamlMappingNode) yaml.Documents[0].RootNode;

                foreach (var entry in mapping.Children)
                {
                    var key = (YamlScalarNode) entry.Key;
                    var value = (YamlMappingNode) entry.Value;

                    //The behavior structure allows the configuration of injectable arguments and password field
                    //This is the reason. The format merges the two concepts.

                    //Loading the properties for each entry
                    string beNamespace = GetField(entry, "namespace", true);
                    string beClassName = GetField(entry, "className", true);
                    string beMember = GetField(entry, "member",true);
                    string beName = GetField(entry,"name",true);
                    //--Method behavior
                    string beInjectableArguments = GetField(entry, "injectableArguments",defaultValue:"");
                    string bePasswordArguments = GetField(entry, "passwordArguments", defaultValue: "");
                    string beArgTypes = GetField(entry, "argTypes");
                    //--Field behavior
                    bool beInjectableField = bool.Parse(GetField(entry, "injectableField", defaultValue: "false"));
                    bool bePasswordField = bool.Parse(GetField(entry, "passwordField", defaultValue: "false"));
                    //--Localisation
                    string beLocale = GetField(entry, "locale");
                    string beLocalePass = GetField(entry, "localePass");

                    string beTaintFromArguments = GetField(entry, "taintFromArguments", defaultValue: "");


                    //Converting the list of index to array
                    int[] argumentsIndexes = convertToIntArray(beInjectableArguments.Split(','));
                    int[] passwordIndexes = convertToIntArray(bePasswordArguments.Split(','));
                    int[] taintFromArgumentsIndexes = convertToIntArray(beTaintFromArguments.Split(','));

                    foreach (var locale in new string[] { beLocale, beLocalePass })
                    {
                        if (locale != null && !descriptors.ContainsKey(locale))
                        {
                            descriptors.Add(locale, LocaleUtil.GetDescriptor(locale));
                        }
                    }
                    
                    
                    //Validate that 'argumentsIndexes' field 
                    if ((!beInjectableField && !bePasswordField) //Not a field signatures, arguments indexes is expected.
                        && argumentsIndexes.Length == 0 
                        && passwordIndexes.Length == 0 
                        && taintFromArgumentsIndexes.Length == 0)
                    {
                        throw new Exception("The method behavior " + key + " is not missing injectableArguments or passwordArguments property");
                    }

                    //Injection based vulnerability
                    string globalKey = beArgTypes != null ? //
                        (beNamespace + "." + beClassName + "|" + beName + "|" + beArgTypes) : //With arguments types discriminator
                        (beNamespace + "." + beClassName + "|" + beName); //Minimalist configuration
                    

                    methodInjectableArguments.Add(globalKey, 
                        new MethodBehavior(argumentsIndexes, passwordIndexes, taintFromArgumentsIndexes, 
                            beLocale, beLocalePass, beInjectableField, bePasswordField));


                    //SGLogging.Log(beNamespace);
                }

                //SGLogging.Log(methodInjectableArguments.Count + " signatures loaded.");
            }
        }

        private string GetField(KeyValuePair<YamlNode, YamlNode> node, string field, bool mandatory = false, string defaultValue = null) {
            try { 
                return ((YamlScalarNode)((YamlMappingNode)node.Value).Children[new YamlScalarNode(field)]).Value;
            }
            catch (KeyNotFoundException) {
                if(mandatory)
                    throw new Exception(string.Format("Unable to load the property {} in node {}",field,node.Key));
                return defaultValue;
            }
        }

        public DiagnosticDescriptor[] GetDescriptors() {
            DiagnosticDescriptor[] descArray = new DiagnosticDescriptor[descriptors.Count];
            descriptors.Values.CopyTo(descArray, 0);
            return descArray;
        }

        /// <summary>
        /// Equivalent to : 
        /// <code>Array.ConvertAll(arrayString, int.Parse)</code>
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        private int[] convertToIntArray(string[] arrayStrings) {
            if (arrayStrings.Length == 1 && arrayStrings[0].Trim() == "")
                return new int[0];
            int[] newArray = new int[arrayStrings.Length];
            
            for (int i=0; i<arrayStrings.Length;i++) {
                newArray[i] = int.Parse(arrayStrings[i]);
            }
            return newArray;
        }

        /// <summary>
        /// Get the method behavior for a given symbol
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        public MethodBehavior GetMethodBehavior(ISymbol symbol) {
            if (symbol == null)
            { //The symbol was not properly resolved
                return null;
            }

            string key = symbol.ContainingType + "|" + symbol.Name;

            MethodBehavior behavior;
            if (methodInjectableArguments.TryGetValue(key, out behavior))
                return behavior;

            if (symbol.ToString().Contains("(")) { //Find a signature with parameter type discrimator
                string keyExtended = symbol.ContainingType.ContainingNamespace + "." + symbol.ContainingType.Name + "|" + symbol.Name + "|" + ExtractParameterSignature(symbol);
                if (methodInjectableArguments.TryGetValue(keyExtended, out behavior))
                    return behavior;
            }

            return null;
        }

        private string ExtractParameterSignature(ISymbol symbol) {
            var firstParenthese = symbol.ToString().IndexOf("(");
            return symbol.ToString().Substring(firstParenthese);
        }

    }
}
