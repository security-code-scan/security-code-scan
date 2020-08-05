#nullable disable
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Text;
using System.Runtime.InteropServices;
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
            new Lazy<string>(() =>
                             {
                                 // todo: use Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) once on netstandard 2.0
                                 string path;
                                 if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                 {
                                     path = Environment.GetEnvironmentVariable("LocalAppData");
                                 }
                                 else
                                 {
                                     string home = Environment.GetEnvironmentVariable("HOME");
                                     // "$XDG_DATA_HOME defines the base directory relative to which user specific data files should be stored."
                                     // "If $XDG_DATA_HOME is either not set or empty, a default equal to $HOME/.local/share should be used."
                                     path = Environment.GetEnvironmentVariable("XDG_DATA_HOME");

                                     if (string.IsNullOrEmpty(path) || path[0] != '/')
                                     {
                                         path = Path.Combine(home, ".local", "share");
                                     }
                                 }

                                 return Path.Combine(path, UserConfigName);
                             });

        private static readonly Version ConfigVersion = new Version(2,1);

        private T DeserializeAndValidate<T>(StreamReader reader, bool validate) where T : ConfigData
        {
            if (validate)
            {
                var yaml = new YamlStream();
                yaml.Load(reader); // throws if duplicates are found
                reader.BaseStream.Seek(0, SeekOrigin.Begin);
            }

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
                        throw new ArgumentException($"Version mismatch in the project configuration file '{file.Path}'. Please read https://security-code-scan.github.io/#ReleaseNotes for the information what has changed in the configuration format.",
                                                    "Version");

                    return projectConfig;
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
            if (userConfig != null)
            {
                var ret = new ConfigData();
                ret.Merge(configuration);
                ret.Merge(userConfig);
                if (project != null)
                    ret.Merge(project);

                return ret;
            }

            if (project != null)
            {
                var ret = new ConfigData();
                ret.Merge(configuration);
                ret.Merge(project);
                return ret;
            }

            return configuration;
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
            if (config2.TaintTypes != null)
            {
                foreach (var taintType in config2.TaintTypes)
                {
                    if (config1.TaintTypes == null)
                        config1.TaintTypes = new List<string>();

                    config1.TaintTypes.Add(taintType);
                }
            }

            if (config2.ReportAnalysisCompletion.HasValue)
                config1.ReportAnalysisCompletion = config2.ReportAnalysisCompletion.Value;

            if (config2.AuditMode.HasValue)
                config1.AuditMode = config2.AuditMode.Value;

            if (config2.MinimumPasswordValidatorProperties.HasValue)
                config1.MinimumPasswordValidatorProperties = config2.MinimumPasswordValidatorProperties.Value;

            if (config2.PasswordValidatorRequiredLength.HasValue)
                config1.PasswordValidatorRequiredLength = config2.PasswordValidatorRequiredLength.Value;

            if (config2.PasswordValidatorRequiredProperties != null)
            {
                foreach (var property in config2.PasswordValidatorRequiredProperties)
                {
                    if (config1.PasswordValidatorRequiredProperties == null)
                        config1.PasswordValidatorRequiredProperties = new List<string>();

                    config1.PasswordValidatorRequiredProperties.Add(property);
                }
            }

            if (config2.Behavior != null)
            {
                foreach (var behavior in config2.Behavior)
                {
                    if (config1.Behavior == null)
                        config1.Behavior = new Dictionary<string, object>();

                    if (behavior.Value == default(MethodBehaviorData))
                        config1.Behavior.Remove(behavior.Key);
                    else
                        config1.Behavior[behavior.Key] = behavior.Value;
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

            if (config2.CsrfProtection != null)
            {
                foreach (var data in config2.CsrfProtection)
                {
                    if (config1.CsrfProtection == null)
                        config1.CsrfProtection = new Dictionary<string, CsrfProtectionData>();

                    if (data.Value == default(CsrfProtectionData))
                        config1.CsrfProtection.Remove(data.Key);
                    else
                        config1.CsrfProtection[data.Key] = data.Value;
                }
            }

            if (config2.PasswordFields != null)
            {
                foreach (var field in config2.PasswordFields)
                {
                    if (config1.PasswordFields == null)
                        config1.PasswordFields = new List<string>();

                    config1.PasswordFields.Add(field);
                }
            }

            if (config2.WebConfigFiles != null)
            {
                config1.WebConfigFiles = config2.WebConfigFiles;
            }

            if (config2.ConstantFields != null)
            {
                foreach (var field in config2.ConstantFields)
                {
                    if (config1.ConstantFields == null)
                        config1.ConstantFields = new List<string>();

                    config1.ConstantFields.Add(field);
                }
            }
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
        public Dictionary<string, CsrfProtectionData>  CsrfProtection                      { get; set; }
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
