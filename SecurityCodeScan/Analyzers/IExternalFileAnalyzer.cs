using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    internal interface IExternalFileAnalyzer
    {
        void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context);
    }
}
