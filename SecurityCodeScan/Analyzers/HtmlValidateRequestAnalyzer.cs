#nullable disable
using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class HtmlValidateRequestAnalyzer : DiagnosticAnalyzer, IExternalFileAnalyzer
    {
        public static readonly DiagnosticDescriptor RuleValidateRequest = LocaleUtil.GetDescriptor("SCS0021");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleValidateRequest);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);

            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            context.RegisterCompilationAction(OnCompilationAction);
        }

        private void OnCompilationAction(CompilationAnalysisContext ctx)
        {
            foreach (AdditionalText file in ctx.Options
                                               .AdditionalFiles
                                               .Where(file =>
                                                      {
                                                          var ext = Path.GetExtension(file.Path);
                                                          if (0 != String.Compare(ext, ".aspx", StringComparison.OrdinalIgnoreCase))
                                                              return false;

                                                          if (!File.Exists(file.Path))
                                                              return false; // happens... let's avoid the AD0001 exception

                                                          return true;
                                                      }))
            {
                AnalyzeFile(file, ctx);
            }
        }

        private static readonly Regex Regex = new Regex(@"<%\s*@\s*Page[^>]+validateRequest\s*=\s*""\s*false\s*""",
                                                        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
                                                        TimeSpan.FromSeconds(60));

        public void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context)
        {
            var text    = file.GetText();
            var content = text.ToString();
            foreach (Match match in Regex.Matches(content))
            {
                context.ReportDiagnostic(ExternalDiagnostic.Create(RuleValidateRequest,
                                                                   file.Path,
                                                                   text.Lines.GetLinePosition(match.Index).Line + 1,
                                                                   match.Value));
            }
        }
    }
}
