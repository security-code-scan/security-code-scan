using System.Collections.Generic;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Config
{
    internal class Configuration
    {
        public Configuration()
        {
            PasswordValidatorRequiredProperties = new HashSet<string>();
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            AntiCsrfAttributes                  = new Dictionary<string, List<string>>();
            PasswordFields                      = new HashSet<string>();
            ConstantFields                      = new HashSet<string>();
        }

        public Configuration(Configuration config)
        {
            AuditMode                           = config.AuditMode;
            PasswordValidatorRequiredLength     = config.PasswordValidatorRequiredLength;
            MinimumPasswordValidatorProperties  = config.MinimumPasswordValidatorProperties;
            PasswordValidatorRequiredProperties = new HashSet<string>(config.PasswordValidatorRequiredProperties);
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Behavior);
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Sinks);
            AntiCsrfAttributes                  = new Dictionary<string, List<string>>(config.AntiCsrfAttributes);
            PasswordFields                      = new HashSet<string>(config.PasswordFields);
            ConstantFields                      = new HashSet<string>(config.ConstantFields);
        }

        public Configuration(ConfigData configData) : this()
        {
            AuditMode                          = configData.AuditMode                          ?? false;
            MinimumPasswordValidatorProperties = configData.MinimumPasswordValidatorProperties ?? 0;
            PasswordValidatorRequiredLength    = configData.PasswordValidatorRequiredLength    ?? 0;

            if (configData.PasswordValidatorRequiredProperties != null)
            {
                foreach (var data in configData.PasswordValidatorRequiredProperties)
                {
                    PasswordValidatorRequiredProperties.Add(data);
                }
            }

            foreach (var data in configData.Behavior)
            {
                Behavior[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var data in configData.Sinks)
            {
                Sinks[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var data in configData.CsrfProtectionAttributes)
            {
                AddAntiCsrfTAttributeToConfiguration(data);
            }

            foreach (var data in configData.PasswordFields)
            {
                PasswordFields.Add(data.ToUpperInvariant());
            }

            foreach (var data in configData.ConstantFields)
            {
                ConstantFields.Add(data);
            }
        }

        public bool                                                     AuditMode;
        public int                                                      PasswordValidatorRequiredLength;
        public int                                                      MinimumPasswordValidatorProperties;
        public HashSet<string>                                          PasswordValidatorRequiredProperties;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Behavior;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Sinks;
        public Dictionary<string, List<string>>                         AntiCsrfAttributes;
        public HashSet<string>                                          PasswordFields;
        public HashSet<string>                                          ConstantFields;

        public void MergeWith(ConfigData config)
        {
            if (config.AuditMode.HasValue)
                AuditMode = config.AuditMode.Value;

            if (config.MinimumPasswordValidatorProperties.HasValue)
                MinimumPasswordValidatorProperties = config.MinimumPasswordValidatorProperties.Value;

            if (config.PasswordValidatorRequiredLength.HasValue)
                PasswordValidatorRequiredLength = config.PasswordValidatorRequiredLength.Value;

            if (config.PasswordValidatorRequiredProperties != null)
            {
                foreach (var property in config.PasswordValidatorRequiredProperties)
                {
                    PasswordValidatorRequiredProperties.Add(property);
                }
            }

            if (config.Behavior != null)
            {
                foreach (var behavior in config.Behavior)
                {
                    if (behavior.Value == default(MethodBehaviorData))
                        Behavior.Remove(behavior.Key);
                    else
                        Behavior[behavior.Key] = CreateBehavior(behavior.Value);
                }
            }

            if (config.Sinks != null)
            {
                foreach (var sink in config.Sinks)
                {
                    if (sink.Value == default(MethodBehaviorData))
                        Sinks.Remove(sink.Key);
                    else
                        Sinks[sink.Key] = CreateBehavior(sink.Value);
                }
            }

            if (config.CsrfProtectionAttributes != null)
            {
                foreach (var data in config.CsrfProtectionAttributes)
                {
                    AddAntiCsrfTAttributeToConfiguration(data);
                }
            }

            if (config.PasswordFields != null)
            {
                foreach (var field in config.PasswordFields)
                {
                    PasswordFields.Add(field.ToUpperInvariant());
                }
            }

            if (config.ConstantFields != null)
            {
                foreach (var field in config.ConstantFields)
                {
                    ConstantFields.Add(field);
                }
            }
        }

        public static KeyValuePair<string, MethodBehavior> CreateBehavior(MethodBehaviorData behavior)
        {
            var key = behavior.ArgTypes != null ?
                          $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}|{behavior.ArgTypes}" : //With arguments types discriminator
                          $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}";                      //Minimalist configuration

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(behavior.InjectableArguments,
                                                                                    behavior.PasswordArguments,
                                                                                    behavior.TaintFromArguments,
                                                                                    behavior.Locale,
                                                                                    behavior.LocalePass,
                                                                                    behavior.InjectableField,
                                                                                    behavior.IsPasswordField));
        }

        public void AddAntiCsrfTAttributeToConfiguration(CsrfProtectionData csrfData)
        {
            AntiCsrfAttributes.TryGetValue(csrfData.HttpMethodsNameSpace, out var list);
            if (list == null)
            {
                list                                              = new List<string>();
                AntiCsrfAttributes[csrfData.HttpMethodsNameSpace] = list;
            }

            list.Add(csrfData.AntiCsrfAttribute);
        }
    }
}
