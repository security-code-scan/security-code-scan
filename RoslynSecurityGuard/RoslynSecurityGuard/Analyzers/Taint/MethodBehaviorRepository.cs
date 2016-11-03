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

            using (Stream stream = assembly.GetManifestResourceStream("RoslynSecurityGuard."+configurationFile))
            using (StreamReader reader = new StreamReader(stream))
            {
                var yaml = new YamlStream();
                yaml.Load(reader);

                var mapping = (YamlMappingNode) yaml.Documents[0].RootNode;

                foreach (var entry in mapping.Children)
                {
                    var key = (YamlScalarNode) entry.Key;
                    var value = (YamlMappingNode) entry.Value;

                    //Loading the properties for each entry
                    string beNamespace = ((YamlScalarNode)value.Children[new YamlScalarNode("namespace")]).Value;
                    string beClassName = ((YamlScalarNode)value.Children[new YamlScalarNode("className")]).Value;
                    string beMember = ((YamlScalarNode)value.Children[new YamlScalarNode("member")]).Value;
                    string beName = ((YamlScalarNode)value.Children[new YamlScalarNode("name")]).Value;
                    string beInjectableArguments = "";
                    try
                    {
                        beInjectableArguments = ((YamlScalarNode)value.Children[new YamlScalarNode("injectableArguments")]).Value;
                    }
                    catch (KeyNotFoundException) { }
                    string bePasswordArguments = "";
                    try
                    {
                        bePasswordArguments = ((YamlScalarNode)value.Children[new YamlScalarNode("passwordArguments")]).Value;
                    }
                    catch (KeyNotFoundException) { }
                    string beLocale = ((YamlScalarNode)value.Children[new YamlScalarNode("locale")]).Value;

                    //Converting the list of index to array
                    int[] argumentsIndexes = convertToIntArray(beInjectableArguments.Split(','));
                    int[] passwordIndexes = convertToIntArray(bePasswordArguments.Split(','));

                    if (!descriptors.ContainsKey(beLocale)) {
                        var newDescriptor = LocaleUtil.GetDescriptor(beLocale);
                        descriptors.Add(beLocale, newDescriptor);
                    }

                    if (argumentsIndexes.Length == 0 && passwordIndexes.Length == 0) {
                        throw new Exception("The method behavior "+ key+ " is not missing injectableArguments or passwordArguments property");
                    }

                    //Injection based vulnerability
                    methodInjectableArguments.Add(beNamespace + "." + beClassName + "|" + beName, new MethodBehavior(argumentsIndexes, passwordIndexes, beLocale));

                    //SGLogging.Log(beNamespace);
                }

                //SGLogging.Log(methodInjectableArguments.Count + " signatures loaded.");
            }
        }

        public DiagnosticDescriptor[] GetDescriptors() {
            DiagnosticDescriptor[] foos = new DiagnosticDescriptor[descriptors.Count];
            descriptors.Values.CopyTo(foos, 0);
            return foos;
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
        /// 
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        public MethodBehavior GetInjectableMethodBehavior(ISymbol symbol) {
            if (symbol == null)
            { //The symbol was not properly resolved
                return null;
            }

            string key = symbol.ContainingType + "|" + symbol.Name;

            MethodBehavior behavior = null;
            methodInjectableArguments.TryGetValue(key, out behavior);
            return behavior;
        }

    }
}
