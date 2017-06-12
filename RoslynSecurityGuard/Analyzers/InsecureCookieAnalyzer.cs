using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Taint;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class InsecureCookieAnalyzer : TaintAnalyzerExtension
    {
        public const string DiagnosticIdSecure = "SG0008";
        private static DiagnosticDescriptor RuleSecure = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const string DiagnosticIdHttpOnly = "SG0009";
        private static DiagnosticDescriptor RuleHttpOnly = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public InsecureCookieAnalyzer()
        {
            TaintAnalyzer.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context)
        {
        }

        public override void VisitStatement(CSharpSyntax.StatementSyntax statement, ExecutionState state)
        {
            var localDeclaration = statement as CSharpSyntax.LocalDeclarationStatementSyntax;
            if (localDeclaration == null) return;
            var varDeclaration = localDeclaration.Declaration as CSharpSyntax.VariableDeclarationSyntax;
            if (varDeclaration == null) return;

            foreach (var variable in varDeclaration.Variables)
            {

                //Looking for the creation of a cookie (HttpCookie)

                var variableDecorator = variable as CSharpSyntax.VariableDeclaratorSyntax;
                if (variableDecorator != null)
                {
                    var expressionValue = variableDecorator.Initializer?.Value;
                    if (expressionValue is CSharpSyntax.ObjectCreationExpressionSyntax)
                    {
                        var objCreation = (CSharpSyntax.ObjectCreationExpressionSyntax)expressionValue;

                        var symbol = state.GetSymbol(objCreation);
                        if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", ".ctor"))
                        {
                            //It will override the initial state
                            state.AddNewValue(variableDecorator.Identifier.Text, //
                                new VariableState(variable, VariableTaint.SAFE) //
                                    .AddTag(VariableTag.HttpCookie));
                        }
                    }
                }
            }
        }

        //public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        //{
        //    //Looking for Assigment to Secure or HttpOnly property
        //    var assigment = node;

        //    if (assigment.Left is CSharpSyntax.IdentifierNameSyntax)
        //    {
        //        var identifier = (CSharpSyntax.IdentifierNameSyntax)assigment.Left;

        //        string variableAccess = identifier.Identifier.ValueText;

        //        if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "Secure"))
        //        {
        //            state.AddTag(variableAccess, VariableTag.HttpCookieSecure);
        //        }
        //        else if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "HttpOnly"))
        //        {
        //            state.AddTag(variableAccess, VariableTag.HttpCookieHttpOnly);
        //        }
        //    }
        //}

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            //Looking for Assigment to Secure or HttpOnly property
            var assigment = node;

            if (assigment.Left is CSharpSyntax.MemberAccessExpressionSyntax)
            {
                var memberAccess = (CSharpSyntax.MemberAccessExpressionSyntax)assigment.Left;

                if (memberAccess.Expression is CSharpSyntax.IdentifierNameSyntax)
                {
                    var identifier = (CSharpSyntax.IdentifierNameSyntax)memberAccess.Expression;
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

        public override void VisitEndMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state)
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

        public override void VisitStatement(VBSyntax.StatementSyntax statement, ExecutionState state)
        {
            var localDeclaration = statement as VBSyntax.LocalDeclarationStatementSyntax;
            if (localDeclaration == null) return;

            foreach (var delaration in localDeclaration.Declarators)
            {
                var varDeclaration = delaration as VBSyntax.VariableDeclaratorSyntax;
                if (varDeclaration == null) return;

                foreach (var variable in varDeclaration.Names)
                {
                    var initializer = varDeclaration.Initializer;
                    SyntaxNode expressionValue = null;

                    if (initializer is VBSyntax.EqualsValueSyntax)
                    {
                        VBSyntax.EqualsValueSyntax equalsClause = initializer;
                        expressionValue = equalsClause?.Value;
                    }
                    if (varDeclaration.AsClause is VBSyntax.AsNewClauseSyntax)
                    {
                        var newClause = (VBSyntax.AsNewClauseSyntax)varDeclaration.AsClause;
                        expressionValue = newClause.NewExpression;
                    }

                    if (expressionValue is VBSyntax.ObjectCreationExpressionSyntax)
                    {
                        var objCreation = (VBSyntax.ObjectCreationExpressionSyntax)expressionValue;

                        var symbol = state.GetSymbol(objCreation);
                        if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", ".ctor"))
                        {
                            //It will override the initial state
                            state.AddNewValue(variable.Identifier.Text, //
                                new VariableState(variable, VariableTaint.SAFE) //
                                    .AddTag(VariableTag.HttpCookie));
                        }
                    }
                }
            }
        }

        public override void VisitAssignment(VBSyntax.AssignmentStatementSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            //Looking for Assigment to Secure or HttpOnly property
            var assigment = node;

            if (assigment.Left is VBSyntax.MemberAccessExpressionSyntax)
            {
                var memberAccess = (VBSyntax.MemberAccessExpressionSyntax)assigment.Left;

                if (memberAccess.Expression is VBSyntax.IdentifierNameSyntax)
                {
                    var identifier = (VBSyntax.IdentifierNameSyntax)memberAccess.Expression;
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

        public override void VisitNamedFieldInitializer(VBSyntax.NamedFieldInitializerSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            //Looking for Assigment to Secure or HttpOnly property
            var assigment = node;

            //if (assigment.Name is VBSyntax.MemberAccessExpressionSyntax)
            //{
            //    var memberAccess = (VBSyntax.MemberAccessExpressionSyntax)assigment.Name;

            //    if (memberAccess.Expression is VBSyntax.IdentifierNameSyntax)
            //    {
            //        var identifier = (VBSyntax.IdentifierNameSyntax)memberAccess.Expression;
            //        string variableAccess = identifier.Identifier.ValueText;

            //        if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "Secure"))
            //        {
            //            state.AddTag(variableAccess, VariableTag.HttpCookieSecure);
            //        }
            //        else if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "HttpOnly"))
            //        {
            //            state.AddTag(variableAccess, VariableTag.HttpCookieHttpOnly);
            //        }
            //    }
            //}
        }

        public override void VisitEndMethodDeclaration(VBSyntax.MethodBlockSyntax node, ExecutionState state)
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
