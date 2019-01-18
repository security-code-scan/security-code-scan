using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CSharpAnalyzers : Analyzers
    {
        internal CSharpAnalyzers(params SecurityAnalyzer[] analyzers) : base(analyzers)
        {
        }

        internal CSharpAnalyzers(SecurityAnalyzer analyzer) : base(analyzer)
        {
        }

        public CSharpAnalyzers()
        {
            InitWorkers<TaintAnalyzerExtensionCSharp>(LanguageNames.CSharp);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class VBasicAnalyzers : Analyzers
    {
        internal VBasicAnalyzers(params SecurityAnalyzer[] analyzers) : base(analyzers)
        {
        }

        internal VBasicAnalyzers(SecurityAnalyzer analyzer) : base(analyzer)
        {
        }

        public VBasicAnalyzers()
        {
            InitWorkers<TaintAnalyzerExtensionVisualBasic>(LanguageNames.VisualBasic);
        }
    }

    public abstract class Analyzers : DiagnosticAnalyzer
    {
        private List<SecurityAnalyzer> Workers;

        internal Analyzers(IEnumerable<SecurityAnalyzer> analyzers)
        {
            foreach (var analyzer in analyzers)
            {
                if (!analyzer.GetType().GetCustomAttributes(typeof(SecurityAnalyzerAttribute), false).Any())
                    throw new Exception("Analyzer is derived from SecurityAnalyzer, but doesn't have 'SecurityAnalyzer' attribute.");
            }
            Workers = new List<SecurityAnalyzer>(analyzers);
            InitDiagnostics();
        }

        internal Analyzers(SecurityAnalyzer analyzer)
        {
            if (!analyzer.GetType().GetCustomAttributes(typeof(SecurityAnalyzerAttribute), false).Any())
                throw new Exception("Analyzer is derived from SecurityAnalyzer, but doesn't have 'SecurityAnalyzer' attribute.");

            Workers = new List<SecurityAnalyzer> { analyzer };
            InitDiagnostics();
        }

        internal void InitWorkers<T>(string language) where T : TaintAnalyzerExtension
        {
            Workers = new List<SecurityAnalyzer>();
            var taintExtensions = new List<T>();
            var types           = GetType().Assembly.GetTypes();
            foreach (var type in types)
            {
                if (!type.IsAbstract && typeof(T).IsAssignableFrom(type))
                {
                    taintExtensions.Add((T)Activator.CreateInstance(type));
                }
            }

            foreach (var type in types)
            {
                if (type.IsAbstract)
                    continue;

                var secAttributes = type.GetCustomAttributes(typeof(SecurityAnalyzerAttribute), false)
                                        .Cast<SecurityAnalyzerAttribute>();
                foreach (var attribute in secAttributes)
                {
                    if (attribute.Languages.Contains(language))
                    {
                        if (typeof(TaintAnalyzer<T>).IsAssignableFrom(type))
                        {
                            Workers.Add((SecurityAnalyzer)Activator.CreateInstance(type, taintExtensions.ToArray()));
                        }
                        else
                        {
                            Workers.Add((SecurityAnalyzer)Activator.CreateInstance(type));
                        }
                        break;
                    }
                }
            }

            InitDiagnostics();
        }

        protected Analyzers()
        {
        }

        private void InitDiagnostics()
        {
            var diagnostics = new HashSet<DiagnosticDescriptor>();

            foreach (var worker in Workers)
            {
                foreach (var desc in worker.SupportedDiagnostics)
                {
                    diagnostics.Add(desc);
                }
            }

            Diagnostics = ImmutableArray.Create(diagnostics.ToArray());
        }

        public override void Initialize(AnalysisContext analysisContext)
        {
            var ctx = new SecurityAnalysisContext();
            ctx.Initialize(analysisContext, Workers);
        }

        private ImmutableArray<DiagnosticDescriptor> Diagnostics;

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Diagnostics;
    }
}
