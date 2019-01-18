using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers
{
    internal abstract class SecurityAnalyzer
    {
        public abstract void Initialize(ISecurityAnalysisContext context);

        public abstract ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; }
    }

    [AttributeUsage(AttributeTargets.Class)]
    internal sealed class SecurityAnalyzerAttribute : Attribute
    {
        public string[] Languages { get; }

        public SecurityAnalyzerAttribute(string firstLanguage, params string[] additionalLanguages)
        {
            if (firstLanguage == null)
                throw new ArgumentNullException(nameof(firstLanguage));
            if (additionalLanguages == null)
                throw new ArgumentNullException(nameof(additionalLanguages));
            string[] strArray = new string[additionalLanguages.Length + 1];
            strArray[0] = firstLanguage;
            for (int index = 0; index < additionalLanguages.Length; ++index)
                strArray[index + 1] = additionalLanguages[index];
            this.Languages = strArray;
        }
    }
}
