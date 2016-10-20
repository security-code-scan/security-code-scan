using Microsoft.CodeAnalysis;
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
        private Dictionary<string, MethodBehavior> methodPasswordArguments = new Dictionary<string, MethodBehavior>();


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

                    string beNamespace = ((YamlScalarNode)value.Children[new YamlScalarNode("namespace")]).Value;
                    string beClassName = ((YamlScalarNode)value.Children[new YamlScalarNode("className")]).Value;
                    string beMember = ((YamlScalarNode)value.Children[new YamlScalarNode("member")]).Value;
                    string beName = ((YamlScalarNode)value.Children[new YamlScalarNode("name")]).Value;
                    string beInjectableArguments = ((YamlScalarNode)value.Children[new YamlScalarNode("injectableArguments")]).Value;
                    string beLocale = ((YamlScalarNode)value.Children[new YamlScalarNode("locale")]).Value;

                    int[] argumentsIndexes = convertToIntArray(beInjectableArguments.Split(','));

                    methodInjectableArguments.Add(beNamespace + "." + beClassName + "|" + beName, new MethodBehavior(argumentsIndexes, beLocale));

                    //SGLogging.Log(beNamespace);
                }

                //SGLogging.Log(methodInjectableArguments.Count + " signatures loaded.");
            }
        }

        /// <summary>
        /// Equivalent to : 
        /// <code>Array.ConvertAll(arrayString, int.Parse)</code>
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        private int[] convertToIntArray(string[] arrayStrings) {
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="symbol"></param>
        /// <returns></returns>
        public MethodBehavior GetPasswordMethodBehavior(ISymbol symbol) {

            if (symbol == null) { //The symbol was not properly resolved
                return null;
            }

            string key = symbol.ContainingType + "." + symbol.Name;

            MethodBehavior behavior = null;
            methodInjectableArguments.TryGetValue(key, out behavior);
            return behavior;
        }
    }
}
