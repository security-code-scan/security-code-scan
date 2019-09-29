using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    internal interface ISecurityAnalysisContext
    {
        void RegisterCompilationStartAction(Action<CompilationStartAnalysisContext, Configuration> action);

        void RegisterCompilationAction(Action<CompilationAnalysisContext> action);

        void RegisterSymbolAction(Action<SymbolAnalysisContext> action, SymbolKind kind);
    }

    internal class SecurityAnalysisContext : ISecurityAnalysisContext
    {
        public void Initialize(AnalysisContext analysisContext, IEnumerable<SecurityAnalyzer> workers)
        {
            foreach (var worker in workers)
            {
                worker.Initialize(this);
            }

            analysisContext.RegisterCompilationStartAction(OnCompilationStartAction);
            analysisContext.RegisterCompilationAction(OnCompilationAction);

            if (OnSymbolActions.Keys.Any())
            {
                analysisContext.RegisterSymbolAction(OnSymbolAction, OnSymbolActions.Keys.ToImmutableArray());
            }
        }

        private readonly CompilationAnalyzer FinalAnalyzer = new CompilationAnalyzer();

        private readonly List<Action<CompilationStartAnalysisContext, Configuration>> OnCompilationStartActions = new List<Action<CompilationStartAnalysisContext, Configuration>>();

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            ProjectConfiguration = new ConfigurationManager().GetProjectConfiguration(context.Options.AdditionalFiles);

            foreach (var action in OnCompilationStartActions)
            {
                action(context, ProjectConfiguration);
            }
        }

        private Configuration ProjectConfiguration;

        public void RegisterCompilationStartAction(Action<CompilationStartAnalysisContext, Configuration> action)
        {
            OnCompilationStartActions.Add(action);
        }

        private readonly List<Action<CompilationAnalysisContext>> OnCompilationActions = new List<Action<CompilationAnalysisContext>>();

        private void OnCompilationAction(CompilationAnalysisContext context)
        {
            foreach (var action in OnCompilationActions)
            {
                action(context);
            }

            if (ProjectConfiguration.ReportAnalysisCompletion)
                FinalAnalyzer.OnCompilationAction(context);
        }

        public void RegisterCompilationAction(Action<CompilationAnalysisContext> action)
        {
            OnCompilationActions.Add(action);
        }

        private readonly Dictionary<SymbolKind, List<Action<SymbolAnalysisContext>>> OnSymbolActions = new Dictionary<SymbolKind, List<Action<SymbolAnalysisContext>>>();

        private void OnSymbolAction(SymbolAnalysisContext context)
        {
            foreach (var actions in OnSymbolActions.Values)
            {
                foreach (var action in actions)
                    action(context);
            }
        }

        public void RegisterSymbolAction(Action<SymbolAnalysisContext> action, SymbolKind kind)
        {
            if (!OnSymbolActions.TryGetValue(kind, out var actions))
            {
                actions = new List<Action<SymbolAnalysisContext>>();
                OnSymbolActions.Add(kind, actions);
            }

            actions.Add(action);
        }
    }
}
