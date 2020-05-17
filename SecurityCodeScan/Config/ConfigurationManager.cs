using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.CodeAnalysis;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;

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
            new Lazy<string>(() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), UserConfigName));

        private static readonly Version ConfigVersion = new Version(2,1);

        private T DeserializeAndValidate<T>(StreamReader reader) where T : ConfigData
        {
            var yaml = new YamlStream();
            yaml.Load(reader); // throws if duplicates are found

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            using (var reader2 = new StreamReader(reader.BaseStream))
            {
                var deserializer = new DeserializerBuilder().IgnoreUnmatchedProperties()
                                                            .Build();
                var data = deserializer.Deserialize<T>(reader2);
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

        public ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            foreach (var file in additionalFiles)
            {
                if (Path.GetFileName(file.Path) != ConfigName)
                    continue;

                using (var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(file.GetText().ToString()))))
                {
                    var projectConfig = DeserializeAndValidate<ProjectConfigData>(reader);

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
                        throw new ArgumentException($"Version mismatch in the project configuration file '{file.Path}'. Please read https://security-code-scan.github.io/#ReleaseNotes for the information what has changed in the configuration format.",
                                                    "Version");

                    return projectConfig;
                }
            }

            return null;
        }
    }

    internal class ConfigurationManager
    {
        internal static ConfigurationReader Reader { get; set; } = new ConfigurationReader();

        private static readonly Lazy<ConfigData> CachedBuiltInConfiguration = new Lazy<ConfigData>(() => Reader.GetBuiltinConfiguration());

        public Configuration GetBuiltInAndUserConfiguration()
        {
            var configuration = new Configuration(CachedBuiltInConfiguration.Value);

            var userConfig = Reader.GetUserConfiguration();
            if (userConfig != null)
                configuration.MergeWith(userConfig);

            configuration.PrepareForQueries();
            return configuration;
        }

        public Configuration GetProjectConfiguration(ImmutableArray<AdditionalText> additionalFiles)
        {
            var projectConfig = Reader.GetProjectConfiguration(additionalFiles);
            if (projectConfig == null)
            {
                return GetBuiltInAndUserConfiguration();
            }

            var mergedConfig = new Configuration(GetBuiltInAndUserConfiguration());
            mergedConfig.MergeWith(projectConfig);
            mergedConfig.PrepareForQueries();
            return mergedConfig;
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
        public bool?                                   ReportAnalysisCompletion            { get; set; }
        public bool?                                   AuditMode                           { get; set; }
        public int?                                    PasswordValidatorRequiredLength     { get; set; }
        public int?                                    MinimumPasswordValidatorProperties  { get; set; }
        public List<string>                            PasswordValidatorRequiredProperties { get; set; }
        public Dictionary<string, object>              Behavior                            { get; set; }
        public Dictionary<string, TaintEntryPointData> TaintEntryPoints                    { get; set; }
        public List<CsrfProtectionData>                CsrfProtection                      { get; set; }
        public List<string>                            PasswordFields                      { get; set; }
        public string                                  WebConfigFiles                      { get; set; }
        public List<string>                            ConstantFields                      { get; set; }
        public List<string>                            TaintTypes                          { get; set; }
    }

    internal class Signature
    {
        public string     Namespace { get; set; }
        public string     ClassName { get; set; }
        public string     Name      { get; set; }
        public MethodData Method    { get; set; }
        public FieldData  Field     { get; set; }
    }

    internal class MethodData
    {
        public string        ArgTypes            { get; set; }
        public object[]      InjectableArguments { get; set; }
        public ConditionData If                  { get; set; }
    }

    internal class ConditionData
    {
        public Dictionary<object, object> Condition { get; set; }
        public Dictionary<object, object> Then      { get; set; }
    }

    internal class FieldData
    {
        public object Injectable { get; set; }
    }

    internal class TaintEntryPointData : Signature
    {
    }

    internal class MethodBehaviorData : Signature
    {
    }

    internal class CsrfProtectionData
    {
        public string Name                                      { get; set; }
        public CsrfMessage Message                              { get; set; }
        public List<CsrfAttributeData> AntiCsrfAttributes       { get; set; }
        public CsrfClass Class                                  { get; set; }
        public CsrfMethod Method                                { get; set; }
        public CsrfParameter Parameter                          { get; set; }
    }

    internal class CsrfClass
    {
        public List<string> Name             { get; set; }
        public CsrfIncludeExclude Attributes { get; set; }
    }

    internal class CsrfMethod
    {
        public CsrfIncludeExclude Attributes { get; set; }
    }

    internal class CsrfParameter
    {
        public CsrfIncludeExclude Attributes { get; set; }
    }

    internal class CsrfIncludeExclude
    {
        public List<CsrfAttributeData> Include { get; set; }
        public List<CsrfAttributeData> Exclude { get; set; }
    }

    internal class CsrfAttributeData
    {
        public string Name                          { get; set; }
        public Dictionary<object, object> Condition { get; set; }
    }

    internal class CsrfMessage
    {
        public string Title       { get; set; }
        public string Description { get; set; }
    }
}
