using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class InsecureCookieAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        private readonly InsecureCookieAnalyzer Analyzer = new InsecureCookieAnalyzer();
        public InsecureCookieAnalyzerCSharp()
        {
            TaintAnalyzerCSharp.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context) { }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state)
        {
            Analyzer.CheckState(state);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class InsecureCookieAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        private readonly InsecureCookieAnalyzer Analyzer = new InsecureCookieAnalyzer();
        public InsecureCookieAnalyzerVisualBasic()
        {
            TaintAnalyzerVisualBasic.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context) { }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state)
        {
            Analyzer.CheckState(state);
        }
    }

    internal class InsecureCookieAnalyzer
    {
        public const            string               DiagnosticIdSecure = "SCS0008";
        private static readonly DiagnosticDescriptor RuleSecure         = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const            string               DiagnosticIdHttpOnly = "SCS0009";
        private static readonly DiagnosticDescriptor RuleHttpOnly         = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public void CheckState(ExecutionState state)
        {
            var visited = new HashSet<VariableState>();
            // For every variables registered in state
            foreach (var variableState in state.VariableStates.Values)
            {
                CheckState(variableState, state, visited);
            }
        }

        public void CheckState(VariableState variableState, ExecutionState state, HashSet<VariableState> visited)
        {
            if (!visited.Add(variableState))
                return;

            foreach (var propertyStatesValue in variableState.PropertyStates.Values)
            {
                CheckState(propertyStatesValue, state, visited);
            }

            var symbol = state.GetSymbol(variableState.Node);
            if (symbol == null)
                return;

            // Only if it is the constructor of the HttpCookie instance
            if (!symbol.IsConstructor() || !symbol.ContainingSymbol.ToString().Equals("System.Web.HttpCookie"))
                return;

            var configuration = ConfigurationManager
                                    .Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles);

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
