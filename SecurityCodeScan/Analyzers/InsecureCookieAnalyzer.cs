using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    internal class InsecureCookieAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        private readonly InsecureCookieAnalyzer Analyzer = new InsecureCookieAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            Analyzer.CheckState(state, projectConfiguration);
        }
    }

    internal class InsecureCookieAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        private readonly InsecureCookieAnalyzer Analyzer = new InsecureCookieAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            Analyzer.CheckState(state, projectConfiguration);
        }
    }

    internal class InsecureCookieAnalyzer
    {
        public const            string               DiagnosticIdSecure = "SCS0008";
        private static readonly DiagnosticDescriptor RuleSecure         = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const            string               DiagnosticIdHttpOnly = "SCS0009";
        private static readonly DiagnosticDescriptor RuleHttpOnly         = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public void CheckState(ExecutionState state, Configuration configuration)
        {
            var visited = new HashSet<VariableState>();
            // For every variables registered in state
            foreach (var variableState in state.VariableStates.Values)
            {
                CheckState(variableState, state, visited, configuration);
            }
        }

        private void CheckState(VariableState variableState, ExecutionState state, HashSet<VariableState> visited, Configuration configuration)
        {
            if (!visited.Add(variableState))
                return;

            foreach (var propertyStatesValue in variableState.PropertyStates.Values)
            {
                CheckState(propertyStatesValue, state, visited, configuration);
            }

            var symbol = state.GetSymbol(variableState.Node);
            if (symbol == null)
                return;

            // Only if it is the constructor of the HttpCookie instance
            if (!symbol.IsConstructor() ||
                (!symbol.ContainingSymbol.ToString().Equals("System.Web.HttpCookie") &&
                 !symbol.ContainingSymbol.ToString().Equals("Microsoft.AspNetCore.Http.CookieOptions")))
            {
                return;
            }

            if (!variableState.PropertyStates.TryGetValue("Secure", out var secureState) ||
                (secureState.Taint == VariableTaint.Constant &&
                secureState.Value is bool isSecure && !isSecure) ||
                configuration.AuditMode && secureState.Taint != VariableTaint.Constant)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleSecure, variableState.Node.GetLocation()));
            }

            if (!variableState.PropertyStates.TryGetValue("HttpOnly", out var httpOnly) ||
                (httpOnly.Taint == VariableTaint.Constant &&
                httpOnly.Value is bool isHttpOnly && !isHttpOnly) ||
                configuration.AuditMode && httpOnly.Taint != VariableTaint.Constant)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, variableState.Node.GetLocation()));
            }
        }
    }
}
