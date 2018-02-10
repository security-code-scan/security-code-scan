using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using SyntaxKind = Microsoft.CodeAnalysis.CSharp.SyntaxKind;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class UnknownPasswordApiAnalyzer : TaintAnalyzerExtension
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0015", "title_assignment");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        private readonly List<string> PasswordKeywords = new List<string> // todo: move out to config
        {
            "password",
            "motdepasse",
            "heslo",
            "adgangskode",
            "wachtwoord",
            "salasana",
            "passwort",
            "passord",
            "senha",
            "geslo",
            "clave",
            "losenord",
            "parola",
            "secretkey",
            "pwd"
        };

        public override void Initialize(AnalysisContext context)
        {
            TaintAnalyzer.RegisterExtension(this);
        }

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                             ExecutionState                          state,
                                             MethodBehavior                          behavior,
                                             ISymbol                                 symbol,
                                             VariableState                           variableRightState)
        {
            if (behavior                                                                     != null                               || //Unknown API
                symbol                                                                       == null                               ||
                variableRightState.Taint                                                     != VariableTaint.Constant             ||
                Microsoft.CodeAnalysis.CSharp.CSharpExtensions.Kind(variableRightState.Node) != SyntaxKind.StringLiteralExpression ||
                !IsPasswordField(symbol))
            {
                return;
            }

            var constValue = state.AnalysisContext.SemanticModel.GetConstantValue(variableRightState.Node);
            if (constValue.HasValue && constValue.Value.Equals(""))
                return;

            var varSymbol = state.GetSymbol(variableRightState.Node);
            if (varSymbol != null && varSymbol.IsType("System.String.Empty"))
                return;

            var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
            state.AnalysisContext.ReportDiagnostic(diagnostic);
        }

        public override void VisitAssignment(VisualBasicSyntaxNode node,
                                             ExecutionState        state,
                                             MethodBehavior        behavior,
                                             ISymbol               symbol,
                                             VariableState         variableRightState)
        {
            if (behavior                 != null                   || //Unknown API
                symbol                   == null                   ||
                variableRightState.Taint != VariableTaint.Constant ||
                Microsoft.CodeAnalysis.VisualBasic.VisualBasicExtensions.Kind(variableRightState.Node) !=
                    Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.StringLiteralExpression ||
                !IsPasswordField(symbol))
            {
                return;
            }

            var constValue = state.AnalysisContext.SemanticModel.GetConstantValue(variableRightState.Node);
            if (constValue.HasValue && constValue.Value.Equals(""))
                return;

            var varSymbol = state.GetSymbol(variableRightState.Node);
            if (varSymbol != null && varSymbol.IsType("System.String.Empty"))
                return;

            var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
            state.AnalysisContext.ReportDiagnostic(diagnostic);
        }

        private bool IsPasswordField(ISymbol symbol)
        {
            return PasswordKeywords.Contains(symbol.MetadataName.ToLower());
        }
    }
}
