using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Taint;
using YamlDotNet.Serialization;

namespace SecurityCodeScan.Config
{

    public class ConfigurationManager
    {
        public static ConfigurationManager Instance { get; } = new ConfigurationManager();

        private const string ConfigName = "SCS.config.yml";
        private const string UserConfigPathName = @"SecurityCodeScan/SCS.{0}.config.yml";
        private readonly Dictionary<string, Configuration> ProjectConfigs = new Dictionary<string, Configuration>();
        private readonly Deserializer Deserializer = new Deserializer();

        private Configuration _configuration;
        private Configuration Configuration {
            get
            {
                if (_configuration != null)
                    return _configuration;

                var assembly = typeof(ConfigurationManager).GetTypeInfo().Assembly;

                using (Stream stream = assembly.GetManifestResourceStream($"SecurityCodeScan.Config.{ConfigName}"))
                {
                    using (var reader = new StreamReader(stream))
                    {
                        var configData = Deserializer.Deserialize<ConfigData>(reader);
                        _configuration = ConvertDataToConfig(configData);
                    }
                }

                var userConfigFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                                  string.Format(UserConfigPathName, assembly.GetName().Version));

                if (!File.Exists(userConfigFile))
                    return _configuration;

                using (StreamReader reader = new StreamReader(userConfigFile))
                {
                    var userConfig = Deserializer.Deserialize<ConfigData>(reader);
                    _configuration = MergeConfigData(userConfig);
                }

                return _configuration;
            }
        }

        private Configuration ConvertDataToConfig(ConfigData configData)
        {
            var config = new Configuration();
            var behaviorInfos = configData.Behavior;

            foreach (var data in behaviorInfos)
            {
                config.Behavior[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var data in configData.Sinks)
            {
                config.Sinks[data.Key] = CreateBehavior(data.Value);
            }

            return config;
        }

        private KeyValuePair<string, MethodBehavior> CreateBehavior(MethodBehaviorData behavior)
        {
            var key = behavior.ArgTypes != null ?
                       $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}|{behavior.ArgTypes}": //With arguments types discriminator
                       $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}"; //Minimalist configuration

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(behavior.InjectableArguments,
                                                                                    behavior.PasswordArguments,
                                                                                    behavior.TaintFromArguments,
                                                                                    behavior.Locale,
                                                                                    behavior.LocalePass,
                                                                                    behavior.InjectableField,
                                                                                    behavior.IsPasswordField));
        }

        public Configuration GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            foreach (var file in additionalFiles)
            {
                if (Path.GetFileName(file.Path) != ConfigName)
                    continue;

                if (ProjectConfigs.ContainsKey(file.Path))
                    return ProjectConfigs[file.Path];

                using (var reader = new StreamReader(file.Path))
                {
                    var deserializer   = new Deserializer();
                    var userConfig     = deserializer.Deserialize<ConfigData>(reader);
                    ProjectConfigs[file.Path] = MergeConfigData(userConfig);
                    return ProjectConfigs[file.Path];
                }
            }

            return Configuration;
        }

        public Configuration MergeConfigData(ConfigData config)
        {
            var mergeInto = new Configuration(Configuration);
            if (config.Behavior != null)
            {
                foreach (var behavior in config.Behavior)
                {
                    if (behavior.Value == default(MethodBehaviorData))
                        mergeInto.Behavior.Remove(behavior.Key);
                    else
                        mergeInto.Behavior[behavior.Key] = CreateBehavior(behavior.Value);
                }
            }

            if (config.Sinks != null)
            {
                foreach (var sink in config.Sinks)
                {
                    if (sink.Value == default(MethodBehaviorData))
                        mergeInto.Sinks.Remove(sink.Key);
                    else
                        mergeInto.Sinks[sink.Key] = CreateBehavior(sink.Value);
                }
            }

            return mergeInto;
        }

        public List<KeyValuePair<string, MethodBehavior>> GetBehaviors(ImmutableArray<AdditionalText> additionalFiles)
        {
            var config = GetProjectConfiguration(additionalFiles);

            var behaviorInfos = new List<KeyValuePair<string, MethodBehavior>>(config.Behavior.Values);
            behaviorInfos.AddRange(config.Sinks.Values);
            return behaviorInfos;
        }

        public class ConfigData
        {
            public Dictionary<string, MethodBehaviorData> Behavior { get; set; }
            public Dictionary<string, MethodBehaviorData> Sinks    { get; set; }
        }

        public class MethodBehaviorData
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
    }
}
