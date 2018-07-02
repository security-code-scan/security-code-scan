using System.Collections.Generic;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Config
{
    internal class Configuration
    {
        public Configuration()
        {
            Behavior           = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sinks              = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            AntiCsrfAttributes = new Dictionary<string, List<string>>();
        }

        public Configuration(Configuration config)
        {
            Behavior           = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Behavior);
            Sinks              = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Sinks);
            AntiCsrfAttributes = new Dictionary<string, List<string>>(config.AntiCsrfAttributes);
        }

        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Behavior;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Sinks;
        public Dictionary<string, List<string>>                         AntiCsrfAttributes;
    }
}
