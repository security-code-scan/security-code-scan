using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Taint;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;

namespace SecurityCodeScan.Config
{
    internal class ConfigurationReader
    {
        private const string BuiltinConfigName = "SecurityCodeScan.Config.Main.yml";
        private const string ConfigName        = "SecurityCodeScan.config.yml";
        private const string UserConfigName    = "SecurityCodeScan\\config-{0}.yml";
        private string UserConfigFile => UserConfigFileCached.Value;

        private static readonly Lazy<string> UserConfigFileCached =
            new Lazy<string>(() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), UserConfigName));

        private static readonly Version ConfigVersion = new Version(2,0);

        private readonly char[] Parenthesis = { '(', ')' };

        private void ValidateArgTypes(IEnumerable<Signature> methods)
        {
            if (methods == null)
                return;

            foreach (var method in methods)
            {
                if (method?.ArgTypes == null)
                    continue;

                var argTypes = method.ArgTypes;
                if (argTypes.Length == 0)
                    throw new Exception($"Do not specify 'ArgTypes:' in {method.Namespace}.{method.ClassName}.{method.Name} to match any overload");

                if (argTypes.Trim() != argTypes)
                    throw new Exception($"Leading or trailing white space in {method.Namespace}.{method.ClassName}.{method.Name}");

                if (argTypes[0] != '(' || argTypes[argTypes.Length - 1] != ')')
                    throw new Exception($"Invalid parenthesis in {method.Namespace}.{method.ClassName}.{method.Name}");

                argTypes = argTypes.Substring(1, argTypes.Length - 2);
                if (argTypes.IndexOfAny(Parenthesis) != -1)
                    throw new Exception($"Parenthesis detected inside of 'ArgTypes:' in {method.Namespace}.{method.ClassName}.{method.Name}");

                if (argTypes != string.Empty)
                {
                    foreach (var argType in argTypes.Split(new[] { ", " }, StringSplitOptions.None))
                    {
                        if (argType.Trim() != argType)
                            throw new Exception(
                                $"Leading or trailing white space in argument of {method.Namespace}.{method.ClassName}.{method.Name}");

                        if (!argType.Contains("."))
                            throw new Exception($"Argument type lacks namespace in {method.Namespace}.{method.ClassName}.{method.Name}");

                        if (argType.Contains("this "))
                            throw new Exception($"'this' keyword should be omitted in {method.Namespace}.{method.ClassName}.{method.Name}");

                        var arg = argType;
                        if (argType.Contains("params "))
                            arg = argType.Replace("params ", "");
                        if (argType.Contains("out "))
                            arg = argType.Replace("out ", "");

                        if (arg.Contains(" "))
                            throw new Exception($"Argument name should be omitted in {method.Namespace}.{method.ClassName}.{method.Name}");
                    }
                }
            }
        }

        private T DeserializeAndValidate<T>(StreamReader reader) where T : ConfigData
        {
            var yaml = new YamlStream();
            yaml.Load(reader); // throws if duplicates are found

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            using (var reader2 = new StreamReader(reader.BaseStream))
            {
                var deserializer = new Deserializer();
                var data = deserializer.Deserialize<T>(reader2);
                ValidateArgTypes(data.Behavior?.Values);
                ValidateArgTypes(data.Sinks?.Values);
                ValidateArgTypes(data.Sources?.Values);
                return data;
            }
        }

        public ConfigData GetBuiltinConfiguration()
        {
            var assembly = typeof(ConfigurationManager).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream(BuiltinConfigName))
            {
                using (var reader = new StreamReader(stream))
                {
                    return DeserializeAndValidate<ConfigData>(reader);
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
                return DeserializeAndValidate<ConfigData>(reader);
            }
        }

        public ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles, out string path)
        {
            path = null;

            foreach (var file in additionalFiles)
            {
                if (Path.GetFileName(file.Path) != ConfigName)
                    continue;

                using (var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(file.GetText().ToString()))))
                {
                    var projectConfig = DeserializeAndValidate<ProjectConfigData>(reader);

                    if (new Version(projectConfig.Version) != ConfigVersion)
                        return null;

                    path = file.Path;
                    return projectConfig;
                }
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

    /// <summary>
    /// External YML configuration structure
    /// </summary>
    internal class ConfigData
    {
        public bool?                                  AuditMode                           { get; set; }
        public int?                                   PasswordValidatorRequiredLength     { get; set; }
        public int?                                   MinimumPasswordValidatorProperties  { get; set; }
        public List<string>                           PasswordValidatorRequiredProperties { get; set; }
        public Dictionary<string, MethodBehaviorData> Behavior                            { get; set; }
        public Dictionary<string, SinkData>           Sinks                               { get; set; }
        public Dictionary<string, TaintSourceData>    Sources                             { get; set; }
        public List<CsrfProtectionData>               CsrfProtectionAttributes            { get; set; }
        public List<string>                           PasswordFields                      { get; set; }
        public List<string>                           ConstantFields                      { get; set; }
        public List<string>                           SanitizerTypes                      { get; set; }
    }

    internal class Signature
    {
        public string Namespace { get; set; }
        public string ClassName { get; set; }
        public string Name     { get; set; }
        public string ArgTypes { get; set; }
    }

    internal class TaintSourceData : Signature
    {
        public bool     FromExternalParameters { get; set; }
    }

    internal class MethodBehaviorData : Signature
    {
        // behavior, validator, sanitizer specific
        public Dictionary<object, object> PreConditions      { get; set; }
        public Dictionary<object, object> PostConditions     { get; set; }

    }

    internal class SinkData : Signature
    {
        public object[] InjectableArguments { get; set; }
        public object   InjectableField     { get; set; }
        public string   Locale              { get; set; }

        // password sink specific
        public int[] PasswordArguments { get; set; }
        public bool  IsPasswordField   { get; set; }
    }

    internal class CsrfProtectionData
    {
        public string HttpMethodsNameSpace { get; set; }
        public string AntiCsrfAttribute    { get; set; }
    }
}
