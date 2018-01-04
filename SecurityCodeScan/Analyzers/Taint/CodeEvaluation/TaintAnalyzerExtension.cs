using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers.Taint
{
    public abstract class TaintAnalyzerExtension : DiagnosticAnalyzer
    {
        // (i) C#.
        public virtual void VisitStatement(CSharpSyntax.StatementSyntax node, ExecutionState state) { }
        public virtual void VisitInvocationAndCreation(CSharpSyntax.ExpressionSyntax node, CSharpSyntax.ArgumentListSyntax argList, ExecutionState state) { }
        public virtual void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState) { }
        public virtual void VisitBeginMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state) { }
        public virtual void VisitEndMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state) { }

        // (ii) Visual Basic
        public virtual void VisitStatement(VBSyntax.StatementSyntax node, ExecutionState state) { }
        public virtual void VisitInvocationAndCreation(VBSyntax.ExpressionSyntax node, VBSyntax.ArgumentListSyntax argList, ExecutionState state) { }
        public virtual void VisitAssignment(VisualBasicSyntaxNode node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState) { }
        public virtual void VisitBeginMethodDeclaration(VBSyntax.MethodBlockSyntax node, ExecutionState state) { }
        public virtual void VisitEndMethodDeclaration(VBSyntax.MethodBlockSyntax node, ExecutionState state) { }
    }
}
