using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Taint;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class UnknownPasswordApiAnalyzer : TaintAnalyzerExtension
    {

        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0015");
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        private List<string> PasswordKeywords = new List<string> {"password", "motdepasse", "heslo", "adgangskode", "wachtwoord", "salasana", "passwort", "passord",
            "senha","geslo", "clave", "losenord", "clave", "parola", "secretkey", "pwd"};

        public override void Initialize(AnalysisContext context)
        {
            TaintAnalyzer.RegisterExtension(this);
        }
        
        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            if (behavior == null && //Unknown API
                    (symbol != null && IsPasswordField(symbol)) &&
                    variableRightState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }


        public override void VisitAssignment(VBSyntax.AssignmentStatementSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            if (behavior == null && //Unknown API
                    (symbol != null && IsPasswordField(symbol)) &&
                    variableRightState.taint == VariableTaint.CONSTANT //Only constant
        )
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }

        public override void VisitNamedFieldInitializer(VBSyntax.NamedFieldInitializerSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            if (behavior == null && //Unknown API
                    (symbol != null && IsPasswordField(symbol)) &&
                    variableRightState.taint == VariableTaint.CONSTANT //Only constant
        )
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
