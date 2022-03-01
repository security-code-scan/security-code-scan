#nullable disable
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.CodeAnalysis;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using SecurityCodeScan.Analyzers.Taint;
using System.Text.RegularExpressions;

namespace SecurityCodeScan.Config
{
    /// <summary>
    /// The implementation must be thread-safe because it is used as static field!
    /// </summary>
    internal class ConfigurationReader
    {
        private const string BuiltinConfigName = "SecurityCodeScan.Config.Main.yml";
        private const string ConfigName        = "SecurityCodeScan.config.yml";
        private const string UserConfigName    = "SecurityCodeScan\\config-{0}.yml";
        private string UserConfigFile => UserConfigFileCached.Value;

        private static readonly Lazy<string> UserConfigFileCached =
            new Lazy<string>(() =>
                             {
                                 string path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                                 return Path.Combine(path, UserConfigName);
                             });

        private static readonly Version ConfigVersion = new Version(3,1);

        public T DeserializeAndValidate<T>(StreamReader reader, bool validate)
        {
            if (validate)
            {
                var yaml = new YamlStream();
                yaml.Load(reader); // throws if duplicates are found
                reader.BaseStream.Seek(0, SeekOrigin.Begin);
            }

            var deserializer = new DeserializerBuilder().IgnoreUnmatchedProperties()
                                                            .WithNodeDeserializer(new ValueTupleNodeDeserializer())
                                                            .Build();
            var data = deserializer.Deserialize<T>(reader);
            return data;
        }

        public ConfigData GetBuiltinConfiguration()
        {
            var assembly = typeof(ConfigurationManager).GetTypeInfo().Assembly;

            using (Stream stream = assembly.GetManifestResourceStream(BuiltinConfigName))
            {
                using (var reader = new StreamReader(stream))
                {
#if DEBUG
                    return DeserializeAndValidate<ConfigData>(reader, validate: true);
#else
                    return DeserializeAndValidate<ConfigData>(reader, validate: false);
#endif
                }
            }
        }

        public virtual ConfigData GetUserConfiguration()
        {
            var filePath = string.Format(UserConfigFile, ConfigVersion);
            if (!File.Exists(filePath))
                return null;

            using (var reader = File.OpenText (filePath))
            {
                return DeserializeAndValidate<ConfigData>(reader, validate: true);
            }
        }

        public ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            foreach (var file in additionalFiles)
            {
                if (Path.GetFileName(file.Path) != ConfigName)
                    continue;

                using (var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(file.GetText().ToString()))))
                {
                    var projectConfig = DeserializeAndValidate<ProjectConfigData>(reader, validate: true);

                    Version projectConfigVersion;
                    try
                    {
                        projectConfigVersion = new Version(projectConfig.Version);
                    }
                    catch (Exception e)
                    {
                        throw new ArgumentException($"'Version' is missing or corrupted in the project configuration file '{file.Path}'. See https://security-code-scan.github.io/#ExternalConfigurationFiles",
                                                    "Version",
                                                    e);
                    }

                    if (projectConfigVersion != ConfigVersion)
                        throw new ArgumentException($"Version mismatch in the project configuration file '{file.Path}'. Please see https://github.com/security-code-scan/security-code-scan/blob/vs2019/SecurityCodeScan/Config/Main.yml for an example of the latest configuration format.",
                                                    "Version");

                    reader.BaseStream.Seek(0, SeekOrigin.Begin);
                    return DeserializeAndValidate<ConfigData>(reader, validate: true);
                }
            }

            return null;
        }
    }

    internal static class ConfigurationManager
    {
        internal static ConfigurationReader Reader { get; set; } = new ConfigurationReader();

        private static readonly Lazy<ConfigData> CachedBuiltInConfiguration = new Lazy<ConfigData>(() => Reader.GetBuiltinConfiguration());

        public static ConfigData GetBuiltInAndUserConfiguration(ConfigData project = null)
        {
            var configuration = CachedBuiltInConfiguration.Value;
            var userConfig = Reader.GetUserConfiguration();
            if (userConfig == null && project == null && AdditionalConfiguration.Path == null)
            {
                // happy path - no `new ConfigData` is needed
                return configuration;
            }
            else
            {
                var ret = new ConfigData();
                ret.Merge(configuration);

                if (userConfig != null)
                {
                    ret.Merge(userConfig);
                }

                if (project != null)
                {
                    ret.Merge(project);
                }

                if (AdditionalConfiguration.Path != null)
                {
                    using (var reader = File.OpenText(AdditionalConfiguration.Path))
                    {
                        ret.Merge(ConfigurationManager.Reader.DeserializeAndValidate<ConfigData>(reader, validate: true));
                    }
                }

                return ret;
            }
        }

        public static ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            var projectConfig = Reader.GetProjectConfiguration(additionalFiles);
            return GetBuiltInAndUserConfiguration(projectConfig);
        }
    }

    internal static class ConfigDataExtensions
    {
        public static void Merge(this ConfigData config1, ConfigData config2)
        {
            if (config2.ReportAnalysisCompletion.HasValue)
                config1.ReportAnalysisCompletion = config2.ReportAnalysisCompletion.Value;

            if (config2.AuditMode.HasValue)
                config1.AuditMode = config2.AuditMode.Value;

            if (config2.MinimumPasswordValidatorProperties.HasValue)
                config1.MinimumPasswordValidatorProperties = config2.MinimumPasswordValidatorProperties.Value;

            if (config2.MaxInterproceduralMethodCallChain.HasValue)
                config1.MaxInterproceduralMethodCallChain = config2.MaxInterproceduralMethodCallChain.Value;

            if (config2.MaxInterproceduralLambdaOrLocalFunctionCallChain.HasValue)
                config1.MaxInterproceduralLambdaOrLocalFunctionCallChain = config2.MaxInterproceduralLambdaOrLocalFunctionCallChain.Value;

            if (config2.PasswordValidatorRequiredLength.HasValue)
                config1.PasswordValidatorRequiredLength = config2.PasswordValidatorRequiredLength.Value;

            if (config2.PasswordValidatorRequiredProperties != null)
            {
                foreach (var property in config2.PasswordValidatorRequiredProperties)
                {
                    if (config1.PasswordValidatorRequiredProperties == null)
                        config1.PasswordValidatorRequiredProperties = new HashSet<string>();

                    config1.PasswordValidatorRequiredProperties.Add(property);
                }
            }

            if (config2.TaintEntryPoints != null)
            {
                foreach (var source in config2.TaintEntryPoints)
                {
                    if (config1.TaintEntryPoints == null)
                        config1.TaintEntryPoints = new Dictionary<string, TaintEntryPointData>();

                    if (source.Value == default(TaintEntryPointData))
                        config1.TaintEntryPoints.Remove(source.Key);
                    else
                        config1.TaintEntryPoints[source.Key] = source.Value;
                }
            }

            if (config2.Sinks != null)
            {
                foreach (var source in config2.Sinks)
                {
                    if (config1.Sinks == null)
                        config1.Sinks = new List<Sink>();

                    config1.Sinks.Add(source);
                }
            }

            if (config2.Sanitizers != null)
            {
                foreach (var sanitizer in config2.Sanitizers)
                {
                    if (config1.Sanitizers == null)
                        config1.Sanitizers = new List<Sanitizer>();

                    config1.Sanitizers.Add(sanitizer);
                }
            }

            if (config2.Transfers != null)
            {
                foreach (var transfer in config2.Transfers)
                {
                    if (config1.Transfers == null)
                        config1.Transfers = new List<Transfer>();

                    config1.Transfers.Add(transfer);
                }
            }

            if (config2.TaintSources != null)
            {
                foreach (var source in config2.TaintSources)
                {
                    if (config1.TaintSources == null)
                        config1.TaintSources = new List<TaintSource>();

                    config1.TaintSources.Add(source);
                }
            }

            if (config2.CsrfCheck != null)
            {
                foreach (var data in config2.CsrfCheck)
                {
                    if (config1.CsrfCheck == null)
                        config1.CsrfCheck = new Dictionary<string, AttributeCheck>();

                    if (data.Value == default(AttributeCheck))
                        config1.CsrfCheck.Remove(data.Key);
                    else
                        config1.CsrfCheck[data.Key] = data.Value;
                }
            }

            if (config2.AuthorizeCheck != null)
            {
                foreach (var data in config2.AuthorizeCheck)
                {
                    if (config1.AuthorizeCheck == null)
                        config1.AuthorizeCheck = new Dictionary<string, AttributeCheck>();

                    if (data.Value == default(AttributeCheck))
                        config1.AuthorizeCheck.Remove(data.Key);
                    else
                        config1.AuthorizeCheck[data.Key] = data.Value;
                }
            }

            if (config2.WebConfigFiles != null)
            {
                config1.WebConfigFiles = config2.WebConfigFiles;
            }
        }
    }

    internal class ProjectConfigData
    {
        public string Version { get; set; }
    }

    /// <summary>
    /// External YML configuration structure
    /// </summary>
    internal class ConfigData
    {
        public uint?                                   MaxInterproceduralMethodCallChain                { get; set; }
        public uint?                                   MaxInterproceduralLambdaOrLocalFunctionCallChain { get; set; }
        public bool?                                   ReportAnalysisCompletion            { get; set; }
        public bool?                                   AuditMode                           { get; set; }
        public int?                                    PasswordValidatorRequiredLength     { get; set; }
        public int?                                    MinimumPasswordValidatorProperties  { get; set; }
        public HashSet<string>                         PasswordValidatorRequiredProperties { get; set; }
        public Dictionary<string, TaintEntryPointData> TaintEntryPoints                    { get; set; }
        public List<TaintSource>                       TaintSources                        { get; set; }
        public List<Sink>                              Sinks                               { get; set; }
        public List<Sanitizer>                         Sanitizers                          { get; set; }
        public List<Transfer>                          Transfers                           { get; set; }
        public Dictionary<string, AttributeCheck>      CsrfCheck                           { get; set; }
        public Dictionary<string, AttributeCheck>      AuthorizeCheck                      { get; set; }
        public string                                  WebConfigFiles                      { get; set; }
    }

    internal class Transfer
    {
        public string Type { get; set; }

        public bool? IsInterface { get; set; }

        public List<TransferInfo> Methods { get; set; }
    }

    internal class Sanitizer
    {
        public string Type { get; set; }

        public HashSet<TaintType> TaintTypes { get; set; }

        public bool? IsInterface { get; set; }

        public List<TransferInfo> Methods { get; set; }
    }

    internal class TransferInfo
    {
        public string Name { get; set; }

        public int? ArgumentCount { get; set; }

        public string[] Signature { get; set; }

        public string[] SignatureNot { get; set; }

        public (string inArgumentName, string outArgumentName)[] InOut { get; set; }

        public (int idx, object value)[] Condition { get; set; }

        public bool? CleansInstance { get; set; }
    }

    internal class Sink
    {
        public string Type { get; set; }

        public HashSet<TaintType> TaintTypes { get; set; }

        public bool? IsAnyStringParameterInConstructorASink { get; set; }

        public bool? IsInterface { get; set; }

        public HashSet<string> Properties { get; set; }

        public SinkMethod[] Methods { get; set; }
    }

    internal class SinkMethod
    {
        public string Name { get; set; }

        public (string argName, object value)[] Condition { get; set; }

        public string[] Arguments { get; set; }
    }

    internal class Method
    {
        public Regex NameRegex { get; private set; }

        private string _Name;
        public string Name
        {
            get
            {
                return _Name;
            }
            set
            {
                if (value != null && value[0] == '/')
                {
                    if (value.Length < 2 || value[value.Length - 1] != '/')
                        throw new ArgumentException("Method.Name");

                    NameRegex = new Regex(value.Substring(1, value.Length - 2), RegexOptions.Compiled);
                }

                _Name = value;
            }
        }

        public HashSet<Accessibility> Accessibility { get; set; }

        public bool? IncludeConstructor { get; set; }

        public bool? Static { get; set; }

        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal class Suffix
    {
        public string Text { get; set; }

        public bool IncludeParent { get; set; }
    }

    internal class Class
    {
        public Suffix Suffix { get; set; }

        public string Parent { get; set; }

        public HashSet<Accessibility> Accessibility { get; set; }

        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal class Parameter
    {
        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal class TaintEntryPointData
    {
        public HashSet<string> Dependency { get; set; }
        public Class Class { get; set; }

        public Method Method { get; set; }

        public Parameter Parameter { get; set; }
    }

    internal class TaintSource
    {
        public string Type { get; set; }

        public HashSet<TaintType> TaintTypes { get; set; }

        public bool? IsInterface { get; set; }

        public string[] Properties { get; set; }

        public string[] Methods { get; set; }
    }

    internal class AttributeCheck
    {
        public HashSet<string> Dependency                   { get; set; }
        public string Name                                  { get; set; }
        public AttributeCheckMessage Message                { get; set; }
        public AttributeCheckIncludeExclude RequiredAttributes { get; set; }
        public Class Class                                  { get; set; }
        public Method Method                                { get; set; }
        public Parameter Parameter                          { get; set; }
    }

    internal class AttributeCheckIncludeExclude
    {
        public List<AttributeCheckData> Include { get; set; }
        public List<AttributeCheckData> Exclude { get; set; }
    }

    internal class AttributeCheckData
    {
        public string Type                                { get; set; }
        public List<Dictionary<object, object>> Condition { get; set; }
    }

    internal class AttributeCheckMessage
    {
        public string Title       { get; set; }
        public string Description { get; set; }
    }
}
