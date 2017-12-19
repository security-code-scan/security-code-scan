using System.Resources;
using System.Globalization;
using RoslynSecurityGuard.Analyzers.Taint;
using System.IO;
using System.Reflection;
using YamlDotNet.RepresentationModel;
using System.Collections.Generic;
using System;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers.Locale
{
    public class YamlResourceManager : ResourceManager
    {
        private const string RESOURCE_FILE = "Messages.yml";

        private IDictionary<string, string> LocaleString = new Dictionary<string, string>();

        public YamlResourceManager() : base("RoslynSecurityGuard.Empty", typeof(YamlResourceManager).GetTypeInfo().Assembly) {
            
        }

        public void Load() {
            var assembly = typeof(YamlResourceManager).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream("RoslynSecurityGuard.Config." + RESOURCE_FILE))
            using (StreamReader reader = new StreamReader(stream))
            {
                var yaml = new YamlStream();
                yaml.Load(reader);

                var mapping = (YamlMappingNode)yaml.Documents[0].RootNode;

                foreach (var entry in mapping.Children)
                {
                    var key = (YamlScalarNode)entry.Key;
                    var value = (YamlMappingNode)entry.Value;

                    string messTitle = ((YamlScalarNode)value.Children[new YamlScalarNode("title")]).Value;
                    string messDescription = ((YamlScalarNode)value.Children[new YamlScalarNode("description")]).Value;

                    LocaleString[key.Value + "_Title"] = messTitle;
                    LocaleString[key.Value + "_Description"] = messDescription;
                    //SGLogging.Log(key.Value);
                }

                //SGLogging.Log(LocaleString.Count + " locales loaded.");
            }
        }

        public new string GetString(string name) {
            return GetString(name, CultureInfo.CurrentCulture);
        }

        public override string GetString(string name, CultureInfo culture) {
            string val;
            if (!LocaleString.TryGetValue(name, out val))
                return "??" + name + "??";

            return val;
        }
    }
}
