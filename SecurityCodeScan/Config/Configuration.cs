using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Linq;
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
            SanitizerTypeNameToBit              = new Dictionary<string, ulong>(62);
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
            SanitizerTypeNameToBit              = new Dictionary<string, ulong>(config.SanitizerTypeNameToBit);
        }

        public Configuration(ConfigData configData) : this()
        {
            if (configData.SanitizerTypes != null)
                RegisterSanitizerTypes(configData.SanitizerTypes);

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
        public Dictionary<string, ulong>                                SanitizerTypeNameToBit;

        public void MergeWith(ConfigData config)
        {
            if (config.SanitizerTypes != null)
                RegisterSanitizerTypes(config.SanitizerTypes);

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

        private void RegisterSanitizerTypes(List<string> typeNames)
        {
            var availableBit = 1ul << 3;
            foreach (var registeredBit in SanitizerTypeNameToBit.Values)
            {
                if (availableBit <= registeredBit)
                    availableBit = registeredBit;
            }

            foreach (var typeName in typeNames)
            {
                if (SanitizerTypeNameToBit.ContainsKey(typeName))
                    throw new Exception("Duplicate sanitizer type");

                if (availableBit == 0ul)
                    throw new Exception("Max number of sanitizer types reached");

                SanitizerTypeNameToBit[typeName] = availableBit;
                availableBit                     = availableBit << 1;
            }
        }

        private ReadOnlyDictionary<int, object> GetPreConditions(object[] arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var preConditions = new Dictionary<int, object>(arguments.Length);
            foreach (var argument in arguments)
            {
                if (argument is Dictionary<object, object> d && d.Count == 1)
                {
                    var obj = d.First();
                    var idx = int.Parse((string)obj.Key);
                    var conditions = (List<object>)obj.Value;
                    if (conditions.Count == 1)
                    {
                        if (conditions[0] is Dictionary<object, object> conditionsDictionary &&
                            conditionsDictionary.Count == 1)
                        {
                            var condition = conditionsDictionary.First();
                            if ((string)condition.Key == "Value")
                            {
                                var value = (string)condition.Value;
                                if (int.TryParse(value, out var intVal))
                                    preConditions.Add(idx, intVal);
                                else
                                    preConditions.Add(idx, value);
                            }
                        }
                    }
                }
                else
                {
                    throw new Exception("Unknown argument");
                }
            }

            return new ReadOnlyDictionary<int, object>(preConditions);
        }

        private ReadOnlyDictionary<int, ulong> GetArguments(object[] arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var outArguments = new Dictionary<int, ulong>(arguments.Length);
            foreach (var argument in arguments)
            {
                if (argument is string s)
                {
                    outArguments.Add(int.Parse(s), (ulong)VariableTaint.Safe);
                }
                else if (argument is Dictionary<object, object> d && d.Count == 1)
                {
                    var indexToTaintType = d.First();
                    if (indexToTaintType.Value is string sanitizerType)
                    {
                        var i = int.Parse((string)indexToTaintType.Key);
                        ulong sanitizerBit;
                        if (i == -1 && sanitizerType == "Validator") // todo: introduce Validators section in yaml
                            sanitizerBit = 0ul;
                        else
                            sanitizerBit = SanitizerTypeNameToBit[sanitizerType];

                        outArguments.Add(i, sanitizerBit);
                    }
                    else if (indexToTaintType.Value is List<object> sanitizerTypes)
                    {
                        ulong bits = 0ul;
                        foreach (var type in sanitizerTypes)
                        {
                            bits |= SanitizerTypeNameToBit[(string)type];
                        }

                        outArguments.Add(int.Parse((string)indexToTaintType.Key), bits);
                    }
                    else
                    {
                        throw new Exception("Unknown sanitizer type");
                    }
                }
                else
                {
                    throw new Exception("Unknown behavior argument");
                }
            }

            return new ReadOnlyDictionary<int, ulong>(outArguments);
        }

        private ulong GetField(object value)
        {
            if (value == null)
                return 0ul;

            if (value is string s)
            {
                if (s == "true")
                    return (ulong)VariableTaint.Safe;

                return SanitizerTypeNameToBit[s];
            }

            throw new Exception("Unknown injectable argument");
        }

        public KeyValuePair<string, MethodBehavior> CreateBehavior(MethodBehaviorData behavior)
        {
            var key = behavior.ArgTypes != null ?
                          $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}|{behavior.ArgTypes}" : //With arguments types discriminator
                          $"{behavior.Namespace}.{behavior.ClassName}|{behavior.Name}";                      //Minimalist configuration

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(GetArguments(behavior.InjectableArguments),
                                                                                    behavior.PasswordArguments?.ToImmutableHashSet(),
                                                                                    GetArguments(behavior.TaintFromArguments),
                                                                                    GetPreConditions(behavior.PreConditions),
                                                                                    GetArguments(behavior.PostConditions),
                                                                                    behavior.Locale,
                                                                                    behavior.LocalePass,
                                                                                    GetField(behavior.InjectableField),
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
