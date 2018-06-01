using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecurityCodeScan.Test.Helpers;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Test.Config
{
    public abstract class ConfigurationTest : DiagnosticVerifier
    {
        private readonly List<string> FilePaths = new List<string>();
        private readonly string ConfigName = "SCS.config.yml";
        protected AnalyzerOptions CreateAnalyzersOptionsWithConfig(string configSource)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            FilePaths.Add(path);

            Directory.CreateDirectory(path);

            var filePath = Path.Combine(path, ConfigName);
            var file = File.CreateText(filePath);
            file.Write(configSource);
            file.Flush();
            file.Close();

            var additionalTextMock = new Mock<AdditionalText>();
            additionalTextMock.Setup(text => text.Path).Returns(filePath); //The path is read when the diagnostic is report
            var additionalFileText = ImmutableArray.Create(additionalTextMock.Object);

            return new AnalyzerOptions(additionalFileText);
        }

        [ClassCleanup]
        public void DeleteConfig()
        {
            foreach (var path in FilePaths)
            {
                File.Delete(Path.Combine(path, ConfigName));
                Directory.Delete(path);
            }
        }
    }
}
