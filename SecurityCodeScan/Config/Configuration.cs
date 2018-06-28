using System.Collections.Generic;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Config
{
    public class Configuration
    {
        internal Configuration()
        {
            PasswordValidatorRequiredProperties = new HashSet<string>();
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            PasswordFields                      = new HashSet<string>();
        }

        internal Configuration(Configuration config)
        {
            PasswordValidatorRequiredLength     = config.PasswordValidatorRequiredLength;
            MinimumPasswordValidatorProperties  = config.MinimumPasswordValidatorProperties;
            PasswordValidatorRequiredProperties = new HashSet<string>(config.PasswordValidatorRequiredProperties);
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Behavior);
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Sinks);
            PasswordFields                      = new HashSet<string>(config.PasswordFields);
        }

        public int PasswordValidatorRequiredLength;
        public int MinimumPasswordValidatorProperties;
        public HashSet<string> PasswordValidatorRequiredProperties;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Behavior;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Sinks;
        public HashSet<string> PasswordFields;
    }
}
