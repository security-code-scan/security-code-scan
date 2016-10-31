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
    public class InsecureCookieAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticIdSecure = "SG0008";
        private static DiagnosticDescriptor RuleSecure = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const string DiagnosticIdHttpOnly = "SG0009";
        private static DiagnosticDescriptor RuleHttpOnly = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);
        
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleSecure,RuleHttpOnly);
        
        public override void Initialize(AnalysisContext context)
        {

            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;

            if (node == null) { //Not the expected node type
                return;
            }

            var state = new ExecutionState(ctx);

            VisitNodeRecursively(node, state);

            //Assert that HttpCookie were configured
            foreach (var variableState in state.Variables) {
                var st = variableState.Value;
                if (st.tags.Contains(VariableTag.HttpCookie))
                {
                    if (!st.tags.Contains(VariableTag.HttpCookieSecure))
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(RuleSecure, st.node.GetLocation()));
                    }
                    if (!st.tags.Contains(VariableTag.HttpCookieHttpOnly))
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, st.node.GetLocation()));
                    }
                }
            }
        }

        private void VisitNodeRecursively(SyntaxNode node, ExecutionState state)
        {
            //Looking for the creation of a cookie (HttpCookie)
            if (node is VariableDeclaratorSyntax)
            {
                var variableDecorator = (VariableDeclaratorSyntax)node;
                var expressionValue = variableDecorator.Initializer?.Value;
                if (expressionValue is ObjectCreationExpressionSyntax)
                {
                    var objCreation = (ObjectCreationExpressionSyntax)expressionValue;

                    var symbol = state.GetSymbol(objCreation);
                    if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", ".ctor"))
                    {
                        state.AddNewValue(variableDecorator.Identifier.Text, //
                            new VariableState(VariableTaint.SAFE) //
                                .AddTag(VariableTag.HttpCookie) //
                                .AddSyntaxNode(node));
                    }
                }
            }
            //Looking for Assigment to Secure or HttpOnly property
            else if (node is AssignmentExpressionSyntax)
            {
                var assigment = (AssignmentExpressionSyntax)node;

                if (assigment.Left is MemberAccessExpressionSyntax) {
                    var memberAccess = (MemberAccessExpressionSyntax)assigment.Left;

                    if (memberAccess.Expression is IdentifierNameSyntax)
                    {
                        var identifier = (IdentifierNameSyntax)memberAccess.Expression;
                        string variableAccess = identifier.Identifier.ValueText;

                        var symbol = state.GetSymbol(memberAccess);
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

            foreach (var n in node.ChildNodes())
            {
                VisitNodeRecursively(n,state);
            }
        }

        /*
        private string getIdentifier(ExpressionSyntax expression) {
            expression.
        }*/
    }
}
