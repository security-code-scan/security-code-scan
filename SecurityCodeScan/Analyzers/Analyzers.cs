using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Config;

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
            Workers = new Lazy<List<SecurityAnalyzer>>(() => InitWorkers<TaintAnalyzerExtensionCSharp>(LanguageNames.CSharp));
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
            Workers = new Lazy<List<SecurityAnalyzer>>(() => InitWorkers<TaintAnalyzerExtensionVisualBasic>(LanguageNames.VisualBasic));
        }
    }

    public abstract class Analyzers : DiagnosticAnalyzer
    {
        internal Lazy<List<SecurityAnalyzer>> Workers;

        internal Analyzers(IEnumerable<SecurityAnalyzer> analyzers)
        {
            foreach (var analyzer in analyzers)
            {
                if (!analyzer.GetType().GetCustomAttributes(typeof(SecurityAnalyzerAttribute), false).Any())
                    throw new Exception("Analyzer is derived from SecurityAnalyzer, but doesn't have 'SecurityAnalyzer' attribute.");
            }
            Workers = new Lazy<List<SecurityAnalyzer>>(() => new List<SecurityAnalyzer>(analyzers));
            Diagnostics = new Lazy<ImmutableArray<DiagnosticDescriptor>>(InitDiagnostics);
        }

        internal Analyzers(SecurityAnalyzer analyzer)
        {
            if (!analyzer.GetType().GetCustomAttributes(typeof(SecurityAnalyzerAttribute), false).Any())
                throw new Exception("Analyzer is derived from SecurityAnalyzer, but doesn't have 'SecurityAnalyzer' attribute.");

            Workers = new Lazy<List<SecurityAnalyzer>>(() => new List<SecurityAnalyzer> { analyzer });
            Diagnostics = new Lazy<ImmutableArray<DiagnosticDescriptor>>(InitDiagnostics);
        }

        internal List<SecurityAnalyzer> InitWorkers<T>(string language) where T : TaintAnalyzerExtension
        {
            var workers = new List<SecurityAnalyzer>();
            var taintExtensions = new List<T>();
            var types           = GetType().Assembly.DefinedTypes;
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
                            workers.Add((SecurityAnalyzer)Activator.CreateInstance(type, taintExtensions.ToArray()));
                        }
                        else
                        {
                            workers.Add((SecurityAnalyzer)Activator.CreateInstance(type));
                        }
                        break;
                    }
                }
            }

            return workers;
        }

        protected Analyzers()
        {
            Diagnostics = new Lazy<ImmutableArray<DiagnosticDescriptor>>(InitDiagnostics);
        }

        private ImmutableArray<DiagnosticDescriptor> InitDiagnostics()
        {
            var diagnostics = new HashSet<DiagnosticDescriptor>();

            foreach (var worker in Workers.Value)
            {
                foreach (var desc in worker.SupportedDiagnostics)
                {
                    diagnostics.Add(desc);
                }
            }

            return ImmutableArray.Create(diagnostics.ToArray());
        }

        public override void Initialize(AnalysisContext analysisContext)
        {
            // uncomment for debugging visual studio extension
            //if (!Debugger.IsAttached)
            //    Debugger.Launch();

            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                analysisContext.EnableConcurrentExecution();

            var config = new ConfigurationManager().GetBuiltInAndUserConfiguration();
            if (!config.AuditMode)
                analysisContext.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            var ctx = new SecurityAnalysisContext();
            ctx.Initialize(analysisContext, Workers.Value);
        }

        private readonly Lazy<ImmutableArray<DiagnosticDescriptor>> Diagnostics;

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Diagnostics.Value;
    }
}
