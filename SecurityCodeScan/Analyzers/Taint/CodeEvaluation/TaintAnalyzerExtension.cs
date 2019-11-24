using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Config;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers.Taint
{
    internal abstract class TaintAnalyzerExtension
    {
        public abstract ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; }
    }

    internal abstract class TaintAnalyzerExtensionCSharp : TaintAnalyzerExtension
    {
        public virtual void VisitBegin(SyntaxNode node, ExecutionState state,
                                       Configuration projectConfiguration) { }
        public virtual void VisitEnd(SyntaxNode   node, ExecutionState state,
                                     Configuration projectConfiguration) { }

        public virtual void VisitStatement(CSharpSyntax.StatementSyntax node,
                                           ExecutionState state,
                                           VariableState statementState,
                                           Configuration projectConfiguration) { }

        public virtual void VisitArrowExpressionClause(CSharpSyntax.ArrowExpressionClauseSyntax node,
                                                       ExecutionState state,
                                                       VariableState statementState,
                                                       Configuration projectConfiguration)
        { }

        public virtual void VisitInvocationAndCreation(CSharpSyntax.ExpressionSyntax   node,
                                                       CSharpSyntax.ArgumentListSyntax argList,
                                                       ExecutionState                  state,
                                                       Configuration                   projectConfiguration) { }

        public virtual void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                            ExecutionState                          state,
                                            MethodBehavior                          behavior,
                                            ISymbol                                 symbol,
                                            VariableState                           variableRightState,
                                            Configuration                           projectConfiguration) { }
    }

    internal abstract class TaintAnalyzerExtensionVisualBasic : TaintAnalyzerExtension
    {
        public virtual void VisitBegin(SyntaxNode     node,
                                       ExecutionState state,
                                       Configuration  projectConfiguration) { }

        public virtual void VisitEnd(SyntaxNode     node,
                                     ExecutionState state,
                                     Configuration  projectConfiguration) { }

        public virtual void VisitStatement(VBSyntax.StatementSyntax node,
                                           ExecutionState           state,
                                           VariableState            statementState,
                                           Configuration            projectConfiguration) { }

        public virtual void VisitInvocationAndCreation(VBSyntax.ExpressionSyntax   node,
                                                       VBSyntax.ArgumentListSyntax argList,
                                                       ExecutionState              state,
                                                       Configuration               projectConfiguration) { }

        public virtual void VisitAssignment(VisualBasicSyntaxNode node,
                                            ExecutionState        state,
                                            MethodBehavior        behavior,
                                            ISymbol               symbol,
                                            VariableState         variableRightState,
                                            Configuration         projectConfiguration) { }
    }
}
