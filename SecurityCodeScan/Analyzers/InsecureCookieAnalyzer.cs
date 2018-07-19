using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;

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

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                             ExecutionState                          state,
                                             MethodBehavior                          behavior,
                                             ISymbol                                 symbol,
                                             VariableState                           variableRightState)
        {
            Analyzer.VisitAssignment(symbol, variableRightState);
        }

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

        public override void VisitAssignment(VisualBasicSyntaxNode node,
                                             ExecutionState        state,
                                             MethodBehavior        behavior,
                                             ISymbol               symbol,
                                             VariableState         variableRightState)
        {
            Analyzer.VisitAssignment(symbol, variableRightState);
        }

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

        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public void VisitAssignment(ISymbol                   symbol,
                                    VariableState             variableRightState)
        {
            var variableValue = variableRightState.Value;
            if (variableRightState.Taint != VariableTaint.Constant)
                variableValue = null;

            if (!(variableValue is bool boolValue))
                boolValue = true; // TODO: In case of auditing mode, show warning that value unknown

            //Looking for Assignment to Secure or HttpOnly property
            if(symbol.IsType("System.Web.HttpCookie.Secure"))
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.HttpCookieSecure);
                else
                    variableRightState.RemoveTag(Tag.HttpCookieSecure);
            }
            else if (symbol.IsType("System.Web.HttpCookie.HttpOnly"))
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.HttpCookieHttpOnly);
                else
                    variableRightState.RemoveTag(Tag.HttpCookieHttpOnly);
            }
        }

        public void CheckState(ExecutionState state)
        {
            // For every variables registered in state
            foreach (var variableState in state.VariableStates)
            {
                var st = variableState.Value;

                var symbol = state.GetSymbol(st.Node);
                if (symbol == null)
                    continue;

                // Only if it is the constructor of the PasswordValidator instance
                if (!symbol.IsConstructor() || !symbol.ContainingSymbol.ToString().Equals("System.Web.HttpCookie"))
                    continue;

                if (!st.Tags.Contains(Tag.HttpCookieSecure))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleSecure, st.Node.GetLocation()));
                }

                if (!st.Tags.Contains(Tag.HttpCookieHttpOnly))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, st.Node.GetLocation()));
                }
            }
        }
    }
}
