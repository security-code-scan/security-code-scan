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
    internal class ConfigurationReader
    {
        private const string BuiltinConfigName = "SecurityCodeScan.Config.Main.yml";
        private const string ConfigName        = "SecurityCodeScan.config.yml";
        private const string UserConfigName    = "SecurityCodeScan\\config-{0}.yml";
        private readonly string UserConfigFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), UserConfigName);

        private readonly Version ConfigVersion = new Version(1,0);

        public ConfigData GetBuiltinConfiguration()
        {
            var assembly = typeof(ConfigurationManager).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream(BuiltinConfigName))
            {
                using (var reader = new StreamReader(stream))
                {
                    var deserializer = new Deserializer();
                    return deserializer.Deserialize<ConfigData>(reader);
                }
            }
        }

        public virtual ConfigData GetUserConfiguration()
        {
            var filePath = string.Format(UserConfigFile, ConfigVersion);
            if (!File.Exists(filePath))
                return null;

            using (var reader = new StreamReader(filePath))
            {
                var deserializer = new Deserializer();
                return deserializer.Deserialize<ConfigData>(reader);
            }
        }

        public ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles, out string path)
        {
            path = null;

            foreach (var file in additionalFiles)
            {
                if (Path.GetFileName(file.Path) != ConfigName)
                    continue;

                var deserializer  = new Deserializer();
                var projectConfig = deserializer.Deserialize<ProjectConfigData>(file.GetText().ToString());
                if (new Version(projectConfig.Version) != ConfigVersion)
                    return null;

                path = file.Path;
                return projectConfig;
            }

            return null;
        }
    }

    internal class ConfigurationManager
    {
        public static ConfigurationManager Instance { get; } = new ConfigurationManager();

        private readonly Dictionary<string, Configuration> ProjectConfigs = new Dictionary<string, Configuration>();

        public ConfigurationReader ConfigurationReader { get; set; } = new ConfigurationReader();

        private static readonly object ProjectConfigsLock = new object();
        private static readonly object ConfigurationLock = new object();

        private ConfigurationManager() { }

        private Configuration CachedConfiguration;

        private Configuration Configuration
        {
            get
            {
                lock (ConfigurationLock)
                {
                    if (CachedConfiguration != null)
                        return CachedConfiguration;

                    var builtinConfiguration = ConfigurationReader.GetBuiltinConfiguration();
                    CachedConfiguration = new Configuration(builtinConfiguration);

                    var userConfig = ConfigurationReader.GetUserConfiguration();
                    if (userConfig != null)
                        CachedConfiguration.MergeWith(userConfig);

                    return CachedConfiguration;
                }
            }
        }

        public Configuration GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            lock (ProjectConfigsLock)
            {
                foreach (var file in additionalFiles)
                {
                    if (ProjectConfigs.TryGetValue(file.Path, out var projectConfiguration))
                        return projectConfiguration;
                }

                var projectConfig = ConfigurationReader.GetProjectConfiguration(additionalFiles, out var configPath);
                if (projectConfig == null)
                {
                    return Configuration;
                }

                var mergedConfig = new Configuration(Configuration);
                mergedConfig.MergeWith(projectConfig);
                ProjectConfigs[configPath] = mergedConfig;
                return mergedConfig;
            }
        }

        public IEnumerable<KeyValuePair<string, MethodBehavior>> GetBehaviors(ImmutableArray<AdditionalText> additionalFiles)
        {
            var config = GetProjectConfiguration(additionalFiles);

            var behaviorInfos = new List<KeyValuePair<string, MethodBehavior>>(config.Behavior.Values);
            behaviorInfos.AddRange(config.Sinks.Values);
            return behaviorInfos;
        }

        public IEnumerable<string> GetAntiCsrfAttributes(ImmutableArray<AdditionalText> additionalFiles, string httpMethodsNamespace)
        {
            var config = GetProjectConfiguration(additionalFiles);

            return config.AntiCsrfAttributes[httpMethodsNamespace];
        }
    }

    internal class ProjectConfigData : ConfigData
    {
        public string Version { get; set; }
    }

    internal class ConfigData
    {
        public bool?                                  AuditMode                           { get; set; }
        public int?                                   PasswordValidatorRequiredLength     { get; set; }
        public int?                                   MinimumPasswordValidatorProperties  { get; set; }
        public List<string>                           PasswordValidatorRequiredProperties { get; set; }
        public Dictionary<string, MethodBehaviorData> Behavior                            { get; set; }
        public Dictionary<string, MethodBehaviorData> Sinks                               { get; set; }
        public List<CsrfProtectionData>               CsrfProtectionAttributes            { get; set; }
        public List<string>                           PasswordFields                      { get; set; }
        public List<string>                           ConstantFields                      { get; set; }
    }

    internal class MethodBehaviorData
    {
        public string ClassName           { get; set; }
        // TODO: use member field in taint analysis or remove it completely
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

    internal class CsrfProtectionData
    {
        public string HttpMethodsNameSpace { get; set; }
        public string AntiCsrfAttribute    { get; set; }
    }
}
