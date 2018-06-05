using System.Collections.Generic;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Config
{
    internal class Configuration
    {
        public Configuration()
        {
            Behavior = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sinks    = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
        }

        public Configuration(Configuration config)
        {
            Behavior = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Behavior);
            Sinks    = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Sinks);
        }

        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Behavior;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Sinks;
    }
}
