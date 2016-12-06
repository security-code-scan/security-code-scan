using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public interface TaintAnalyzerExtension
    {

        void VisitStatement(StatementSyntax node, ExecutionState state);

        void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state);

        void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState);



        void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state);

        void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state);


   }
}
