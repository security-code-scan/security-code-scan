using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class UnknownPasswordApiAnalyzer : TaintAnalyzerExtension
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0015");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        private readonly List<string> PasswordKeywords = new List<string>
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
            "clave",
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
            if (behavior                 == null && //Unknown API
                symbol                   != null && IsPasswordField(symbol) &&
                variableRightState.Taint == VariableTaint.Constant //Only constant
            )
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }

        public override void VisitAssignment(VisualBasicSyntaxNode node,
                                             ExecutionState        state,
                                             MethodBehavior        behavior,
                                             ISymbol               symbol,
                                             VariableState         variableRightState)
        {
            if (behavior                 == null && //Unknown API
                symbol                   != null && IsPasswordField(symbol) &&
                variableRightState.Taint == VariableTaint.Constant) //Only constant
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }

        private bool IsPasswordField(ISymbol symbol)
        {
            return PasswordKeywords.Contains(symbol.MetadataName.ToLower());
            //return symbol.MetadataName.ToLower().Contains("password");
        }
    }
}
