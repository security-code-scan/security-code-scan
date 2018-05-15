using System.Collections.Generic;
using System.IO;
using System.Reflection;
using YamlDotNet.Serialization;

namespace SecurityCodeScan.Config
{
    internal static class Configuration
    {
        private const string InternalConfigName = "SCS.config.yml";

        private static ConfigData _config;
        public static ConfigData Config {
            get
            {
                if (_config != null)
                    return _config;

                var assembly = typeof(Configuration).GetTypeInfo().Assembly;
                using (Stream stream = assembly.GetManifestResourceStream($"SecurityCodeScan.Config.{InternalConfigName}"))
                {
                    using (var reader = new StreamReader(stream))
                    {
                        var deserializer = new Deserializer();
                        return _config = deserializer.Deserialize<ConfigData>(reader);
                    }
                }
            }
        }

        public static IList<MethodBehaviorInfo> GetBehaviors()
        {
            var behaviorInfos = new List<MethodBehaviorInfo>(Config.Behavior.Values);
            behaviorInfos.AddRange(Config.Sinks.Values);
            return behaviorInfos;
        }

        public class MethodBehaviorInfo
        {
            public string ClassName           { get; set; }
            public string Member              { get; set; }
            public string Name                { get; set; }
            public string Namespace           { get; set; }
            public string ArgTypes            { get; set; }
            public int[]  InjectableArguments { get; set; }
            public int[]  PasswordArguments   { get; set; }
            public int[]  TaintFromArguments  { get; set; }
            public string Locale              { get; set; }
            public string LocalePass          { get; set; }
            public bool   InjectableField     { get; set; }
            public bool   IsPasswordField     { get; set; }
        }

        public class ConfigData
        {
            public IDictionary<string, MethodBehaviorInfo> Behavior { get; set; }
            public IDictionary<string, MethodBehaviorInfo> Sinks {get; set; }
        }
    }
}
