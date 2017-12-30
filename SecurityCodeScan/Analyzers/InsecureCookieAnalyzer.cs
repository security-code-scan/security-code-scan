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

using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Analyzers.Locale;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class InsecureCookieAnalyzer : TaintAnalyzerExtension
    {
        public const string DiagnosticIdSecure = "SCS0008";
        private static DiagnosticDescriptor RuleSecure = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const string DiagnosticIdHttpOnly = "SCS0009";
        private static DiagnosticDescriptor RuleHttpOnly = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public InsecureCookieAnalyzer()
        {
            TaintAnalyzer.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context)
        {
        }


        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            //Looking for Assigment to Secure or HttpOnly property
            
            if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "Secure"))
            {
                variableRightState.AddTag(VariableTag.HttpCookieSecure);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "HttpOnly"))
            {
                variableRightState.AddTag(VariableTag.HttpCookieHttpOnly);
            }
        }

        public override void VisitEndMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state)
        {
            CheckState(state);
        }


        public override void VisitAssignment(VisualBasicSyntaxNode node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            
            if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "Secure"))
            {
                variableRightState.AddTag(VariableTag.HttpCookieSecure);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, "HttpCookie", "HttpOnly"))
            {
                variableRightState.AddTag(VariableTag.HttpCookieHttpOnly);
            }
        }
        
        public override void VisitEndMethodDeclaration(VBSyntax.MethodBlockSyntax node, ExecutionState state)
        {
            CheckState(state);
        }

        private void CheckState(ExecutionState state)
        {
            // For every variables registered in state
            foreach (var variableState in state.Variables)
            {
                var st = variableState.Value;

                // Only if it is the constructor of the PasswordValidator instance
                if (AnalyzerUtil.SymbolMatch(state.GetSymbol(st.node), "HttpCookie", ".ctor"))
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

    }
}
