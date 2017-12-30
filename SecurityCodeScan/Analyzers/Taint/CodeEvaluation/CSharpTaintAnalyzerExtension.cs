using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace SecurityCodeScan.Analyzers.Taint
{
    public interface CSharpTaintAnalyzerExtension
    {

        void VisitStatement(StatementSyntax node, ExecutionState state);

        void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state);

        void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState);



        void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state);

        void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state);


   }
}
