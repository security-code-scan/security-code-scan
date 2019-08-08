using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Test.Config;

namespace SecurityCodeScan.Test.Audit
{
    public sealed class AuditTest
    {
        private const string ConfigPath = @"Tests\Config\AuditMode.yml";

        // Multi-thread safe initialization, guaranteed to be called only once
        private static readonly Lazy<Task<AnalyzerOptions>> Config = new Lazy<Task<AnalyzerOptions>>(async () =>
                                                                                {
                                                                                    using (var file = File.OpenText(ConfigPath))
                                                                                    {
                                                                                        var testConfig = await file.ReadToEndAsync().ConfigureAwait(false);
                                                                                        return ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
                                                                                    }
                                                                                });

        public static async Task<AnalyzerOptions> GetAuditModeConfigOptions()
        {
            return await Config.Value.ConfigureAwait(false);
        }
    }
}
