using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynSecurityGuard.Analyzers.Taint;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class InsecureCookieAnalyzer : DiagnosticAnalyzer, TaintAnalyzerExtension
    {
        public const string DiagnosticIdSecure = "SG0008";
        private static DiagnosticDescriptor RuleSecure = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const string DiagnosticIdHttpOnly = "SG0009";
        private static DiagnosticDescriptor RuleHttpOnly = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);
        
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleSecure,RuleHttpOnly);

        public InsecureCookieAnalyzer() {
            TaintAnalyzer.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context)
        {
            
        }

        public void VisitStatement(StatementSyntax statement, ExecutionState state)
        {
            var localDeclaration = statement as LocalDeclarationStatementSyntax;
            if (localDeclaration == null) return;
            var varDeclaration = localDeclaration.Declaration as VariableDeclarationSyntax;
            if (varDeclaration == null) return;

            foreach (var variable in varDeclaration.Variables)
            {

                //Looking for the creation of a cookie (HttpCookie)

                var variableDecorator = variable as VariableDeclaratorSyntax;
                if (variableDecorator != null)
                {
                    var expressionValue = variableDecorator.Initializer?.Value;
                    if (expressionValue is ObjectCreationExpressionSyntax)
                    {
                        var objCreation = (ObjectCreationExpressionSyntax)expressionValue;

                        var symbol = state.GetSymbol(objCreation);
                        if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", ".ctor"))
                        {
                            //It will override the initial state
                            state.AddNewValue(variableDecorator.Identifier.Text, //
                                new VariableState(VariableTaint.SAFE) //
                                    .AddTag(VariableTag.HttpCookie) //
                                    .AddSyntaxNode(variable));
                        }
                    }
                }
            }
            
        }


        public void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
        {
            
        }


        public void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {

            //Looking for Assigment to Secure or HttpOnly property
            var assigment = node;

            if (assigment.Left is MemberAccessExpressionSyntax)
            {
                var memberAccess = (MemberAccessExpressionSyntax)assigment.Left;

                if (memberAccess.Expression is IdentifierNameSyntax)
                {
                    var identifier = (IdentifierNameSyntax)memberAccess.Expression;
                    string variableAccess = identifier.Identifier.ValueText;
                    
                    if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "Secure"))
                    {
                        state.AddTag(variableAccess, VariableTag.HttpCookieSecure);
                    }
                    else if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "HttpOnly"))
                    {
                        state.AddTag(variableAccess, VariableTag.HttpCookieHttpOnly);
                    }
                }
            }
        }

        public void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {
            
        }

        public void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {
            //Assert that HttpCookie were configured
            foreach (var variableState in state.Variables)
            {
                var st = variableState.Value;
                if (st.tags.Contains(VariableTag.HttpCookie))
                {
                    if (!st.tags.Contains(VariableTag.HttpCookieSecure))
                    {
                        state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleSecure, st.node.GetLocation()));
                    }
                    if (!st.tags.Contains(VariableTag.HttpCookieHttpOnly))
                    {
                        state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, st.node.GetLocation()));
                    }
                }
            }
        }

        /*
        private string getIdentifier(ExpressionSyntax expression) {
            expression.
        }*/
    }
}
